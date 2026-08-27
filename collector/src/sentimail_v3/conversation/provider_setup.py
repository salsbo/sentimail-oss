from __future__ import annotations

import hashlib
import io
import json
import os
import re
from urllib.parse import quote, urlencode
import tempfile
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Any

import asyncpg
import httpx
import pyzipper

from sentimail_v3.conversation.action_tokens import token_hash
from sentimail_v3.config import Settings
from sentimail_v3.conversation.conversation import strip_quoted_reply
from sentimail_v3.identity import Identity, instance_identity

_TOKEN_RE = re.compile(r"<s3\.([A-Za-z0-9_-]{20,})@[^>]+>")
_PROVIDERS = {
    "deepseek": "deepseek",
    "claude": "anthropic",
    "anthropic": "anthropic",
    "chatgpt": "openai",
    "openai": "openai",
}
_SECRET_FILES = {
    "deepseek": "deepseek_api_key",
    "anthropic": "anthropic_api_key",
    "openai": "openai_api_key",
}
# Mêmes valeurs que la migration 070 : la pose de clé par email choisit
# elle-même le couple (adaptateur technique, URL, paramètre de tokens) au
# lieu d'écrire un nom de fournisseur que la migration devrait retraduire.
# Le 4e élément porte les champs propriétaires exigés dans le corps de la
# requête (ex. couper le raisonnement DeepSeek, régression du 22/08 : son API
# raisonne par défaut et un dossier long épuiserait max_tokens en
# raisonnement, contenu vide à l'arrivée).
_EMAIL_PRESETS = {
    "deepseek": (
        "openai_compatible", "https://api.deepseek.com", "max_tokens",
        {"thinking": {"type": "disabled"}},
    ),
    "openai": (
        "openai_compatible", "https://api.openai.com/v1",
        "max_completion_tokens", {},
    ),
    "anthropic": ("anthropic", "https://api.anthropic.com", "max_tokens", {}),
}
MAX_ZIP_BYTES = 128 * 1024
MAX_KEY_BYTES = 16 * 1024


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _message(raw: bytes) -> EmailMessage:
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    if not isinstance(parsed, EmailMessage):
        raise ValueError("message MIME invalide")
    return parsed


def _sender(message: Message, envelope_from: str) -> str:
    header_sender = parseaddr(str(message.get("From") or ""))[1].casefold()
    envelope_sender = parseaddr(envelope_from)[1].casefold()
    if not header_sender or header_sender != envelope_sender:
        return ""
    return header_sender


def _reply_token(message: Message) -> str | None:
    references = " ".join(
        str(message.get(name) or "") for name in ("In-Reply-To", "References")
    )
    match = _TOKEN_RE.search(references)
    return match.group(1) if match else None


def _body(message: EmailMessage) -> str:
    part = message.get_body(preferencelist=("plain",))
    if part is None:
        return ""
    try:
        return strip_quoted_reply(part.get_content())
    except (LookupError, UnicodeError):
        return ""


# Ce que chaque lien fait ecrire : un seul nom, sur la premiere ligne.
#
# Le 18 aout, une reponse est partie avec l'archive mais sans le nom du
# fournisseur ; le collector l'a refusee en 550 et la cle est revenue dans un
# rapport de non-remise. Demander a quelqu'un d'ecrire exactement un mot parmi
# trois, sans le lui preparer, c'est fabriquer l'erreur.
#
# Le nom doit rester en tete : place apres la citation, il serait efface avec
# elle. Et la prose de la lettre ne cite plus les trois noms, sinon un client
# qui cite sans prefixer par « > » les reinjecterait tous dans la reponse - le
# collector refuserait alors pour l'exces inverse.
_CHOICE_LABELS = {
    "deepseek": "DeepSeek",
    "claude": "Claude",
    "chatgpt": "ChatGPT",
}


def bootstrap_choice_links(action_address: str) -> dict[str, str]:
    """Une reponse prete par fournisseur, le nom deja ecrit."""
    if any(value in action_address for value in ("\r", "\n")):
        raise ValueError("adresse d'action invalide")
    liens: dict[str, str] = {}
    for cle, libelle in _CHOICE_LABELS.items():
        corps = (
            f"{libelle}\n\n"
            "N'oublie pas de joindre le ZIP chiffre contenant cle-api.txt "
            "avant d'envoyer.\n"
        )
        liens[cle] = "mailto:" + action_address + "?" + urlencode(
            {"subject": "Re: [SentiMail] Choisis et configure le moteur de MAIA",
             "body": corps},
            quote_via=quote,
        )
    return liens


def bootstrap_body(action_address: str) -> str:
    """La lettre d'enrolement, avec la reponse toute prete."""
    liens = bootstrap_choice_links(action_address)
    return (
        "Je demarre sans moteur de langage configure.\n\n"
        "Remplis le fichier cle-api.txt joint avec la cle API, et rien d'autre. "
        "Place-le seul dans un ZIP chiffre par mot de passe.\n\n"
        "Puis clique sur le moteur que tu choisis : la reponse s'ouvre deja "
        "redigee, il ne te reste qu'a joindre le ZIP avant d'envoyer.\n\n"
        + "".join(
            f"  {_CHOICE_LABELS[cle]} : {liens[cle]}\n\n"
            for cle in ("deepseek", "claude", "chatgpt")
        )
        + "Je demanderai le mot de passe dans un second email. "
        "Aucun modele ne verra la cle.\n\n"
        "— MAIA, SentiMail V3"
    )


def _names_on(line: str) -> set[str]:
    folded = line.casefold()
    return {
        value
        for alias, value in _PROVIDERS.items()
        if re.search(rf"\b{alias}\b", folded)
    }


def _provider(text: str) -> str | None:
    """Le fournisseur choisi, lu ligne par ligne plutôt que d'un bloc.

    Lire tout le texte d'un seul tenant refusait dès que deux noms
    apparaissaient - or la lettre d'enrôlement en propose trois, et il suffit
    qu'un client les recopie sans les préfixer par « > » pour que la réponse
    devienne illisible. Une ligne qui n'en nomme qu'un est sans ambiguïté ;
    c'est la première de ce genre qui fait foi, et la réponse préparée par les
    liens la place en tête.

    Une ligne qui en nomme plusieurs - « DeepSeek plutôt que Claude » - reste
    ambiguë et n'est pas tranchée : on passe à la suivante.
    """
    for line in text.splitlines():
        names = _names_on(line)
        if len(names) == 1:
            return names.pop()
    return None


def _encrypted_zip(message: EmailMessage) -> bytes:
    candidates: list[bytes] = []
    for part in message.iter_attachments():
        filename = str(part.get_filename() or "").casefold()
        if filename.endswith(".zip") or part.get_content_type() in {
            "application/zip",
            "application/x-zip-compressed",
        }:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                candidates.append(payload)
    if len(candidates) != 1:
        raise ValueError("un unique fichier ZIP est requis")
    archive = candidates[0]
    if not archive or len(archive) > MAX_ZIP_BYTES:
        raise ValueError("le ZIP est vide ou dépasse 128 Kio")
    return archive


def decrypt_api_key(archive: bytes, password: str) -> str:
    if not password or len(password) > 512 or "\x00" in password:
        raise ValueError("mot de passe invalide")
    try:
        with pyzipper.AESZipFile(io.BytesIO(archive)) as zipped:
            members = [item for item in zipped.infolist() if not item.is_dir()]
            if len(members) != 1 or Path(members[0].filename).name.casefold() != "cle-api.txt":
                raise ValueError("le ZIP doit contenir uniquement cle-api.txt")
            member = members[0]
            if not member.flag_bits & 0x1:
                raise ValueError("le ZIP n'est pas chiffré")
            if member.file_size > MAX_KEY_BYTES or member.compress_size > MAX_ZIP_BYTES:
                raise ValueError("le fichier de clé est trop volumineux")
            if member.compress_size and member.file_size / member.compress_size > 20:
                raise ValueError("ratio de compression refusé")
            zipped.setpassword(password.encode("utf-8"))
            secret = zipped.read(member)
    except (RuntimeError, pyzipper.BadZipFile) as exc:
        raise ValueError("mot de passe ou ZIP invalide") from exc
    try:
        key = secret.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("cle-api.txt doit être en UTF-8") from exc
    if len(key) < 20 or len(key) > 4096 or any(char.isspace() for char in key):
        raise ValueError("format de clé API invalide")
    return key


async def validate_api_key(
    client: httpx.AsyncClient, provider: str, key: str, model: str
) -> None:
    if provider == "anthropic":
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            json={
                "model": model,
                "max_tokens": 8,
                "messages": [{"role": "user", "content": "Réponds OK."}],
            },
        )
    else:
        base = "https://api.deepseek.com" if provider == "deepseek" else "https://api.openai.com/v1"
        token_field = "max_tokens" if provider == "deepseek" else "max_completion_tokens"
        response = await client.post(
            f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": "Réponds OK."}],
                token_field: 8,
            },
        )
    if response.status_code in {401, 403}:
        raise ValueError("la clé a été refusée par le fournisseur")
    if response.status_code >= 400:
        raise RuntimeError(f"validation fournisseur temporairement indisponible ({response.status_code})")


def _write_secret(directory: str, filename: str, key: str) -> None:
    target_dir = Path(directory)
    target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".incoming-", dir=target_dir)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(key)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target_dir / filename)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


async def _activate_role_providers(
    connection: asyncpg.Connection,
    provider: str,
    model_name: str,
    filename: str,
    sender: str,
) -> None:
    """Une clé posée par email vaut pour les deux rôles (verdict, conversation)."""
    provider_technique, base_url, token_param, body_extras = _EMAIL_PRESETS[provider]
    await connection.execute(
        """INSERT INTO llm_role_providers
           (role,provider,base_url,model_name,token_limit_param,
            secret_filename,body_extras,validated_at,configured_by)
           SELECT r.role,$1,$2,$3,$4,$5,$6::jsonb,now(),$7
           FROM (VALUES ('verdict'),('conversation')) AS r(role)
           ON CONFLICT (role) DO UPDATE SET provider=EXCLUDED.provider,
             base_url=EXCLUDED.base_url,model_name=EXCLUDED.model_name,
             token_limit_param=EXCLUDED.token_limit_param,
             secret_filename=EXCLUDED.secret_filename,
             body_extras=EXCLUDED.body_extras,
             validated_at=now(),configured_by=EXCLUDED.configured_by,
             updated_at=now()""",
        provider_technique, base_url, model_name, token_param, filename,
        _json(body_extras), sender,
    )


class ProviderSetup:
    def __init__(self, pool: asyncpg.Pool[Any], settings: Settings) -> None:
        self.pool = pool
        self.settings = settings

    async def ensure_bootstrap(self) -> bool:
        identite = await instance_identity(self.pool, self.settings)
        async with self.pool.acquire() as connection, connection.transaction():
            await connection.execute("SELECT pg_advisory_xact_lock(830031)")
            configured = await connection.fetchval("SELECT EXISTS (SELECT 1 FROM llm_role_providers)")
            active = await connection.fetchval(
                """SELECT EXISTS (SELECT 1 FROM llm_provider_setup_sessions
                   WHERE state IN ('awaiting_zip','awaiting_password','validating')
                     AND expires_at > now())"""
            )
            pending = await connection.fetchval(
                """SELECT EXISTS (SELECT 1 FROM smtp_actions
                   WHERE status='pending' AND context->>'purpose'='bootstrap_provider'
                     AND expires_at > now())"""
            )
            if configured or active or pending:
                return False
            conversation_id = await connection.fetchval(
                "INSERT INTO conversations (participant_email,status) VALUES ($1,'awaiting_user') RETURNING id",
                self.settings.operator_address,
            )
            action_id = await connection.fetchval(
                """INSERT INTO smtp_actions
                   (case_id,action,token_hash,reply_address,expires_at,context)
                   VALUES (NULL,'credential_upload',NULL,$1,now()+interval '7 days',$2::jsonb)
                   RETURNING id""",
                identite.action_address,
                _json({"conversation_id": str(conversation_id), "purpose": "bootstrap_provider", "binding": True}),
            )
            await connection.execute(
                """INSERT INTO assistant_outbox
                   (conversation_id,action_id,recipient,sender,reply_to,subject,body_text,
                    attachment_filename,attachment_content_type,attachment_content)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,'cle-api.txt','text/plain',$8)""",
                conversation_id,
                action_id,
                self.settings.operator_address,
                identite.assistant_sender,
                identite.action_address,
                "[SentiMail] Choisis et configure le moteur de MAIA",
                bootstrap_body(identite.action_address),
                b"\n",
            )
            return True

    async def handle(self, raw: bytes, envelope_from: str) -> str | None:
        message = _message(raw)
        token = _reply_token(message)
        if not token:
            return None
        action = await self.pool.fetchrow(
            """SELECT sa.id,sa.context->>'purpose' AS purpose,
                      sa.context->>'conversation_id' AS conversation_id,
                      sa.context->>'setup_id' AS setup_id,c.participant_email
               FROM smtp_actions sa JOIN conversations c
                 ON c.id=NULLIF(sa.context->>'conversation_id','')::uuid
               WHERE sa.token_hash=$1 AND sa.status='pending' AND sa.expires_at>now()""",
            token_hash(token),
        )
        if action is None or action["purpose"] not in {"bootstrap_provider", "credential_password"}:
            return None
        sender = _sender(message, envelope_from)
        if sender != str(action["participant_email"]).casefold():
            await self.pool.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES ('credential_setup','reply.rejected_sender',$1::jsonb)",
                _json({"sender_domain": sender.rsplit("@", 1)[-1] if "@" in sender else "invalid"}),
            )
            return "rejected_sender"
        if action["purpose"] == "bootstrap_provider":
            return await self._receive_zip(message, action, sender)
        return await self._receive_password(message, action, sender)

    async def _receive_zip(self, message: EmailMessage, action: asyncpg.Record, sender: str) -> str:
        provider = _provider(_body(message))
        archive = _encrypted_zip(message)
        if provider is None:
            raise ValueError("indique exactement DeepSeek, Claude ou ChatGPT dans ta réponse")
        model = {
            "deepseek": self.settings.deepseek_assistant_model,
            "anthropic": self.settings.anthropic_model,
            "openai": self.settings.openai_model,
        }[provider]
        identite = await instance_identity(self.pool, self.settings)
        async with self.pool.acquire() as connection, connection.transaction():
            setup_id = await connection.fetchval(
                """INSERT INTO llm_provider_setup_sessions
                   (conversation_id,participant_email,provider,model_name,state,
                    encrypted_zip,encrypted_zip_sha256)
                   VALUES ($1::uuid,$2,$3,$4,'awaiting_password',$5,$6) RETURNING id""",
                action["conversation_id"], sender, provider, model, archive,
                hashlib.sha256(archive).hexdigest(),
            )
            await connection.execute(
                "UPDATE smtp_actions SET status='consumed',consumed_at=now(),requested_by=$2 WHERE id=$1",
                action["id"], sender,
            )
            await self._queue_password_prompt(
                connection, action["conversation_id"], setup_id, provider, None, identite
            )
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES ('credential_setup','zip.accepted',$1::jsonb)",
                _json({"provider": provider, "zip_sha256": hashlib.sha256(archive).hexdigest()}),
            )
        return "credential_zip_accepted"

    async def _queue_password_prompt(
        self, connection: asyncpg.Connection, conversation_id: object,
        setup_id: object, provider: str, error: str | None,
        identite: Identity,
    ) -> None:
        action_id = await connection.fetchval(
            """INSERT INTO smtp_actions
               (case_id,action,token_hash,reply_address,expires_at,context)
               VALUES (NULL,'credential_password',NULL,$1,now()+interval '15 minutes',$2::jsonb)
               RETURNING id""",
            identite.action_address,
            _json({"conversation_id": str(conversation_id), "setup_id": str(setup_id), "purpose": "credential_password", "binding": True}),
        )
        prefix = f"Je n’ai pas pu ouvrir le ZIP ({error}).\n\n" if error else "J’ai reçu le ZIP chiffré.\n\n"
        await connection.execute(
            """INSERT INTO assistant_outbox
               (conversation_id,action_id,recipient,sender,reply_to,subject,body_text)
               VALUES ($1::uuid,$2,$3,$4,$5,$6,$7)""",
            conversation_id, action_id, self.settings.operator_address,
            identite.assistant_sender, identite.action_address,
            f"[SentiMail] Mot de passe pour {provider}",
            prefix + "Réponds à cet email avec uniquement le mot de passe du ZIP. "
            "Cette réponse sera interceptée avant l’archivage et ne sera jamais envoyée à un LLM.\n\n— MAIA",
        )

    async def _receive_password(self, message: EmailMessage, action: asyncpg.Record, sender: str) -> str:
        password = _body(message).strip()
        setup = await self.pool.fetchrow(
            """SELECT * FROM llm_provider_setup_sessions
               WHERE id=$1::uuid AND state='awaiting_password' AND expires_at>now()""",
            action["setup_id"],
        )
        if setup is None:
            return "credential_session_expired"
        identite = await instance_identity(self.pool, self.settings)
        try:
            key = decrypt_api_key(bytes(setup["encrypted_zip"]), password)
            async with httpx.AsyncClient(timeout=httpx.Timeout(20)) as client:
                await validate_api_key(
                    client, str(setup["provider"]), key, str(setup["model_name"])
                )
            filename = _SECRET_FILES[str(setup["provider"])]
            _write_secret(self.settings.provider_secrets_dir, filename, key)
        except (ValueError, RuntimeError) as exc:
            async with self.pool.acquire() as connection, connection.transaction():
                attempts = int(setup["failed_attempts"]) + 1
                await connection.execute(
                    "UPDATE smtp_actions SET status='consumed',consumed_at=now(),requested_by=$2 WHERE id=$1",
                    action["id"], sender,
                )
                if attempts >= 3:
                    await connection.execute(
                        "UPDATE llm_provider_setup_sessions SET state='failed',encrypted_zip=NULL,failed_attempts=$2,updated_at=now() WHERE id=$1",
                        setup["id"], attempts,
                    )
                else:
                    await connection.execute(
                        "UPDATE llm_provider_setup_sessions SET failed_attempts=$2,updated_at=now() WHERE id=$1",
                        setup["id"], attempts,
                    )
                    await self._queue_password_prompt(
                        connection, setup["conversation_id"], setup["id"],
                        str(setup["provider"]), str(exc), identite,
                    )
            return "credential_password_rejected"
        async with self.pool.acquire() as connection, connection.transaction():
            await _activate_role_providers(
                connection, str(setup["provider"]), str(setup["model_name"]), filename, sender,
            )
            await connection.execute(
                "UPDATE llm_provider_setup_sessions SET state='complete',encrypted_zip=NULL,completed_at=now(),updated_at=now() WHERE id=$1",
                setup["id"],
            )
            await connection.execute(
                "UPDATE smtp_actions SET status='consumed',consumed_at=now(),requested_by=$2 WHERE id=$1",
                action["id"], sender,
            )
            await connection.execute(
                """INSERT INTO assistant_outbox
                   (conversation_id,recipient,sender,reply_to,subject,body_text)
                   VALUES ($1,$2,$3,$4,$5,$6)""",
                setup["conversation_id"], sender, identite.assistant_sender,
                identite.action_address, "[SentiMail] MAIA est configurée",
                f"La clé {setup['provider']} a été validée et activée avec le modèle {setup['model_name']}.\n\n"
                "Le ZIP chiffré a été purgé. La clé n’a été ni enregistrée en base, ni envoyée à un LLM, ni écrite dans les logs.\n\n— MAIA",
            )
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES ('credential_setup','provider.activated',$1::jsonb)",
                _json({"provider": setup["provider"], "model": setup["model_name"]}),
            )
        return "credential_provider_activated"
