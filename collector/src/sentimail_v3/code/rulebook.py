from __future__ import annotations

import csv
import io
import json
import re
import unicodedata
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any

import asyncpg

MANAGEMENT_ACTIONS = {
    "list_rules",
    "import_rules",
    "set_sender_rule",
    "update_rule",
    "disable_rule",
    "restore_rule",
}
CLASSIFICATIONS = {"legitimate", "spam", "dangerous", "suspect", "undetermined"}
LIST_ACTIONS = {"allow", "hold"}
_FEEDBACK_ID_RE = re.compile(r"\bF[- ](\d+)\b", re.IGNORECASE)
_POLICY_ID_RE = re.compile(r"\bP[- ]([0-9a-fA-F]{8})\b", re.IGNORECASE)
_LOCAL_PART_RE = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$", re.IGNORECASE)
_DOMAIN_LABEL_RE = re.compile(r"^[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?$", re.IGNORECASE)
_EMAIL_TOKEN_RE = re.compile(
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+", re.IGNORECASE
)
MAX_IMPORT_BYTES = 256 * 1024
MAX_IMPORT_ENTRIES = 1000


@dataclass(frozen=True)
class RuleGate:
    allowed: bool
    reason: str
    rule_id: str | None = None
    classification: str | None = None
    list_action: str | None = None
    sender: str | None = None


@dataclass(frozen=True)
class RuleResponse:
    body: str
    attachment_name: str | None = None
    attachment_content: bytes | None = None
    applied: bool = True


class RuleImportError(ValueError):
    pass


def _normalized(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def _list_action(value: str) -> str | None:
    text = _normalized(value).strip().replace("-", "_").replace(" ", "_")
    if text in {
        "allow",
        "white",
        "whitelist",
        "liste_blanche",
        "blanche",
        "legitime",
    }:
        return "allow"
    if text in {
        "hold",
        "deny",
        "black",
        "blacklist",
        "liste_noire",
        "noire",
        "spam",
        "indesirable",
    }:
        return "hold"
    return None


def _explicit_list_action(value: str) -> str | None:
    text = _normalized(value)
    allow = bool(re.search(r"\b(?:liste\s+)?blanche\b|\bwhitelist\b", text))
    hold = bool(re.search(r"\b(?:liste\s+)?noire\b|\bblacklist\b", text))
    if allow == hold:
        return None
    return "allow" if allow else "hold"


def _normalize_sender_address(value: str) -> str:
    candidate = value.strip()
    if candidate.casefold().startswith("sender="):
        candidate = candidate.split("=", 1)[1].strip()
    address = parseaddr(candidate)[1].strip().casefold()
    if not address or len(address) > 254 or address.count("@") != 1:
        raise RuleImportError(f"adresse email invalide : {value[:120]}")
    local, domain = address.rsplit("@", 1)
    if not _LOCAL_PART_RE.fullmatch(local):
        raise RuleImportError(f"partie locale invalide : {value[:120]}")
    try:
        ascii_domain = domain.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise RuleImportError(f"domaine invalide : {value[:120]}") from exc
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise RuleImportError(f"domaine invalide : {value[:120]}")
    return f"{local}@{ascii_domain}"


def _import_attachment(raw_message: bytes) -> tuple[str, str]:
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    attachments: list[tuple[str, bytes]] = []
    for part in message.walk():
        filename = str(part.get_filename() or "")
        if not filename.casefold().endswith((".csv", ".txt")):
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            attachments.append((filename, payload))
    if len(attachments) != 1:
        raise RuleImportError(
            "joins exactement un fichier CSV ou TXT contenant les adresses à importer"
        )
    filename, payload = attachments[0]
    if not payload or len(payload) > MAX_IMPORT_BYTES or b"\x00" in payload:
        raise RuleImportError("le fichier est vide, trop volumineux ou invalide")
    try:
        return filename, payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RuleImportError("le fichier doit être encodé en UTF-8") from exc


@dataclass(frozen=True)
class ImportReading:
    """Ce qu'un fichier contient de retenu, et ce qu'il faut dire du reste.

    Une liste de mille adresses comporte presque toujours une ligne fautive.
    Tout refuser pour autant obligerait l'utilisateur à recommencer sans savoir
    quoi corriger : on retient donc ce qui est valide, on nomme le reste, et
    c'est lui qui tranche.
    """

    entries: list[tuple[str, str]]
    rejected: list[str]
    filename: str

    @property
    def has_rejects(self) -> bool:
        return bool(self.rejected)


def parse_policy_import(
    raw_message: bytes, default_action: str | None
) -> ImportReading:
    """Lit localement un CSV/TXT ; son contenu n'est jamais envoyé au LLM."""
    filename, text = _import_attachment(raw_message)
    entries: dict[str, str] = {}
    rejected: list[str] = []

    def add(raw_address: str, raw_action: str | None) -> None:
        action = _list_action(raw_action or "") or default_action
        if action not in LIST_ACTIONS:
            raise RuleImportError(
                "chaque ligne doit préciser liste_blanche/liste_noire, ou la directive doit nommer une seule liste"
            )
        address = _normalize_sender_address(raw_address)
        previous = entries.get(address)
        if previous is not None and previous != action:
            raise RuleImportError(
                f"la même adresse figure dans les deux listes : {address}"
            )
        entries[address] = action
        if len(entries) > MAX_IMPORT_ENTRIES:
            raise RuleImportError(
                f"le fichier dépasse la limite de {MAX_IMPORT_ENTRIES} adresses"
            )

    def read(number: int, action: object) -> None:
        """Applique une ligne, ou consigne pourquoi elle est écartée."""
        try:
            action()
        except RuleImportError as exc:
            rejected.append(f"ligne {number} : {exc}")

    if filename.casefold().endswith(".txt"):
        for number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            cells = next(csv.reader([line], delimiter=";" if ";" in line else ","))
            if len(cells) == 2 and _list_action(cells[0]):
                read(number, lambda cells=cells: add(cells[1], cells[0]))
            elif len(cells) == 2 and _list_action(cells[1]):
                read(number, lambda cells=cells: add(cells[0], cells[1]))
            elif len(cells) == 1:
                read(number, lambda cells=cells: add(cells[0], None))
            else:
                rejected.append(f"ligne {number} : format non reconnu")
    else:
        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        table = list(csv.reader(io.StringIO(text), dialect=dialect))
        if not table:
            raise RuleImportError("le fichier CSV ne contient aucune ligne")
        normalized_header = [_normalized(cell).strip() for cell in table[0]]
        email_index = next(
            (
                index
                for index, name in enumerate(normalized_header)
                if name in {"email", "address", "adresse", "sender", "expediteur", "match"}
            ),
            None,
        )
        list_index = next(
            (
                index
                for index, name in enumerate(normalized_header)
                if name in {"list", "liste", "decision", "action"}
            ),
            None,
        )
        status_index = next(
            (index for index, name in enumerate(normalized_header) if name == "status"),
            None,
        )
        kind_index = next(
            (index for index, name in enumerate(normalized_header) if name == "kind"),
            None,
        )
        rows = table[1:] if email_index is not None else table
        for number, row in enumerate(rows, start=2 if email_index is not None else 1):
            if not row or not any(cell.strip() for cell in row):
                continue
            if email_index is not None:
                if len(row) <= email_index:
                    rejected.append(f"ligne {number} : aucune adresse")
                    continue
                if (
                    kind_index is not None
                    and len(row) > kind_index
                    and _normalized(row[kind_index]).strip() not in {"policy", "liste"}
                ):
                    continue
                if (
                    status_index is not None
                    and len(row) > status_index
                    and _normalized(row[status_index]).strip() in {"disabled", "desactive"}
                ):
                    continue
                if row[email_index].strip().casefold().startswith("domain="):
                    continue
                raw_action = row[list_index] if list_index is not None and len(row) > list_index else None
                read(number, lambda row=row, raw_action=raw_action: add(row[email_index], raw_action))
            elif len(row) == 2 and _list_action(row[0]):
                read(number, lambda row=row: add(row[1], row[0]))
            elif len(row) == 2 and _list_action(row[1]):
                read(number, lambda row=row: add(row[0], row[1]))
            elif len(row) == 1:
                read(number, lambda row=row: add(row[0], None))
            else:
                rejected.append(f"ligne {number} : format attendu email,liste")
    if not entries:
        raise RuleImportError(
            "aucune adresse exploitable : "
            + ("; ".join(rejected[:5]) if rejected else "le fichier est vide")
        )
    return ImportReading(sorted(entries.items()), rejected, filename)


async def set_sender_list_policy(
    connection: asyncpg.Connection,
    participant: str,
    sender: str,
    action: str,
    *,
    source: str,
) -> None:
    if action not in LIST_ACTIONS:
        raise ValueError("invalid sender list action")
    normalized_sender = _normalize_sender_address(sender)
    opposite = "hold" if action == "allow" else "allow"
    await connection.execute(
        """
        UPDATE sender_policies SET active=false,updated_at=now()
        WHERE lower(participant_email)=lower($1) AND scope='sender'
          AND value_normalized=$2 AND action=$3 AND active=true
        """,
        participant,
        normalized_sender,
        opposite,
    )
    await connection.execute(
        """
        INSERT INTO sender_policies (
            participant_email,scope,value_normalized,action,active,source
        ) VALUES ($1,'sender',$2,$3,true,$4)
        ON CONFLICT (participant_email,scope,value_normalized,action)
        DO UPDATE SET active=true,source=EXCLUDED.source,updated_at=now()
        """,
        participant,
        normalized_sender,
        action,
        source,
    )


def _rule_ids(value: str) -> list[str]:
    matches = [f"F-{match.group(1)}" for match in _FEEDBACK_ID_RE.finditer(value)]
    matches.extend(f"P-{match.group(1).lower()}" for match in _POLICY_ID_RE.finditer(value))
    return matches


def _explicit_classification(value: str) -> str | None:
    text = _normalized(value)
    patterns = {
        "legitimate": r"\b(legitime|fiable|pas du spam)\b",
        "spam": r"\b(spam|indesirable)\b",
        "dangerous": r"\b(dangereux|malveillant|phishing|hameconnage)\b",
        "suspect": r"\b(suspect|douteux|bizarre)\b",
        "undetermined": r"\b(indetermine|incertain|je ne sais pas)\b",
    }
    matches = [name for name, pattern in patterns.items() if re.search(pattern, text)]
    return matches[0] if len(matches) == 1 else None


def validate_rule_request(user_text: str, result: dict[str, object]) -> RuleGate:
    action = str(result.get("requested_action") or "none")
    if action not in MANAGEMENT_ACTIONS:
        return RuleGate(False, "not_a_rule_request")
    text = _normalized(user_text)
    if action == "list_rules":
        if re.search(
            r"\b(regles?|listes?|apprentissage|memoire|verdicts?)\b", text
        ):
            return RuleGate(True, "read_only_rule_export")
        return RuleGate(False, "rulebook_not_explicitly_requested")
    if action == "import_rules":
        if not re.search(r"\b(importe|importer|ajoute|ajouter|charge|charger)\b", text):
            return RuleGate(False, "list_import_not_explicitly_requested")
        explicit_action = _explicit_list_action(user_text)
        proposed_action = str(result.get("rule_list") or "")
        if proposed_action not in LIST_ACTIONS | {"mixed"}:
            return RuleGate(False, "list_import_kind_missing")
        if explicit_action is not None and proposed_action != explicit_action:
            return RuleGate(False, "list_import_kind_conflict")
        if explicit_action is None and proposed_action != "mixed":
            return RuleGate(False, "mixed_list_import_not_explicit")
        return RuleGate(
            True,
            "authenticated_attachment_import",
            list_action=None if proposed_action == "mixed" else proposed_action,
        )
    if action == "set_sender_rule":
        if not re.search(
            r"\b(ajoute|ajouter|mets|mettre|place|placer|autorise|bloque)\b", text
        ):
            return RuleGate(False, "sender_list_change_not_explicit")
        try:
            addresses = {
                _normalize_sender_address(value)
                for value in _EMAIL_TOKEN_RE.findall(user_text)
            }
            proposed_sender = _normalize_sender_address(
                str(result.get("rule_email") or "")
            )
        except RuleImportError:
            return RuleGate(False, "sender_list_address_invalid")
        if len(addresses) != 1 or proposed_sender not in addresses:
            return RuleGate(False, "sender_list_address_conflict")
        explicit_action = _explicit_list_action(user_text)
        proposed_action = str(result.get("rule_list") or "")
        if explicit_action is None or proposed_action != explicit_action:
            return RuleGate(False, "sender_list_kind_conflict")
        return RuleGate(
            True,
            "explicit_sender_list_change",
            list_action=explicit_action,
            sender=proposed_sender,
        )

    ids = _rule_ids(user_text)
    llm_rule_id = str(result.get("rule_id") or "").upper()
    if len(ids) != 1 or not llm_rule_id or ids[0].upper() != llm_rule_id:
        return RuleGate(False, "missing_or_conflicting_rule_id")
    if action == "disable_rule" and not re.search(
        r"\b(supprime|desactive|retire|oublie)\b", text
    ):
        return RuleGate(False, "disable_not_explicitly_requested")
    if action == "restore_rule" and not re.search(
        r"\b(restaure|reactive|retablis|retablit)\b", text
    ):
        return RuleGate(False, "restore_not_explicitly_requested")
    if action == "update_rule":
        if not re.search(r"\b(corrige|modifie|change|remplace)\b", text):
            return RuleGate(False, "update_not_explicitly_requested")
        explicit = _explicit_classification(user_text)
        proposed = result.get("rule_classification")
        if explicit is None or proposed != explicit:
            return RuleGate(False, "missing_or_conflicting_classification")
        if not ids[0].startswith("F-"):
            return RuleGate(False, "only_feedback_classification_is_editable")
        return RuleGate(True, "explicit_feedback_update", ids[0], explicit)
    return RuleGate(True, "explicit_rule_state_change", ids[0])


def label_sender(from_header: object, envelope_from: object) -> str:
    """Identité du correspondant retenue par le registre d'apprentissage."""
    visible = parseaddr(str(from_header or ""))[1]
    return (visible or str(envelope_from or "")).casefold()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def csv_safe_cell(value: object) -> str:
    text = str(value or "")
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


async def render_rulebook(pool: asyncpg.Pool[Any], participant: str) -> RuleResponse:
    # Le registre lit ses propres colonnes : il survit au dégonflage puis à la
    # suppression du message d'origine par la fenêtre de rétention.
    feedback = await pool.fetch(
        """
        SELECT l.id,l.label,l.active,l.created_at,l.updated_at,
               coalesce(l.sender_normalized, lower(m.envelope_from)) AS sender,
               coalesce(l.subject, m.subject) AS subject,
               l.context->>'feedback_reason_code' AS feedback_reason_code,
               left(coalesce(l.context->>'user_reason',''),2000) AS user_reason
        FROM labels l LEFT JOIN messages m ON m.id=l.message_id
        WHERE l.source='smtp_feedback_user'
          AND (
              lower(l.participant_email)=lower($1)
              OR (
                  l.participant_email IS NULL AND EXISTS (
                      SELECT 1 FROM unnest(m.envelope_recipients) recipient
                      WHERE lower(recipient)=lower($1)
                  )
              )
          )
        ORDER BY l.id
        """,
        participant,
    )
    policies = await pool.fetch(
        """
        SELECT id,scope,value_normalized,action,active,created_at,updated_at
        FROM sender_policies WHERE lower(participant_email)=lower($1)
        ORDER BY created_at,id
        """,
        participant,
    )
    profiles: dict[str, dict[str, int]] = {}
    rows: list[list[str]] = []
    for item in feedback:
        sender = str(item["sender"] or "adresse effacée")
        if item["active"]:
            counts = profiles.setdefault(sender, {name: 0 for name in CLASSIFICATIONS})
            counts[str(item["label"])] += 1
        rows.append(
            [
                f"F-{item['id']}",
                "feedback",
                "active" if item["active"] else "disabled",
                str(item["label"]),
                sender,
                participant,
                str(item["subject"] or ""),
                str(item["updated_at"]),
                str(item["feedback_reason_code"] or ""),
                str(item["user_reason"] or ""),
            ]
        )
    for item in policies:
        decision = {
            "allow": "liste_blanche",
            "hold": "liste_noire",
        }.get(str(item["action"]), str(item["action"]))
        rows.append(
            [
                f"P-{str(item['id'])[:8]}",
                "policy",
                "active" if item["active"] else "disabled",
                decision,
                f"{item['scope']}={item['value_normalized']}",
                participant,
                "",
                str(item["updated_at"]),
                "",
                "",
            ]
        )

    lines = [
        "État du registre d’apprentissage MAIA",
        f"Utilisateur : {participant}",
        "",
        "Profils correspondants actifs :",
    ]
    if not profiles:
        lines.append("- Aucun profil confirmé.")
    for sender, counts in sorted(profiles.items()):
        adverse = counts["spam"] + counts["dangerous"] + counts["suspect"]
        lines.append(
            f"- {sender} : {counts['legitimate']} légitime(s), "
            f"{adverse} défavorable(s), {counts['undetermined']} indéterminé(s)."
        )
    active_allow = [
        str(item["value_normalized"])
        for item in policies
        if item["active"] and item["action"] == "allow" and item["scope"] == "sender"
    ]
    active_hold = [
        str(item["value_normalized"])
        for item in policies
        if item["active"] and item["action"] == "hold" and item["scope"] == "sender"
    ]
    lines.extend(["", "Liste blanche active :"])
    lines.extend([f"- {address}" for address in active_allow] or ["- Vide."])
    lines.extend(["", "Liste noire active :"])
    lines.extend([f"- {address}" for address in active_hold] or ["- Vide."])
    lines.extend(["", "Règles et observations :"])
    if not rows:
        lines.append("- Aucune règle enregistrée.")
    for row in rows:
        reason = f" | motif={row[8]} : {row[9]}" if row[8] or row[9] else ""
        lines.append(
            f"- {row[0]} | {row[2]} | {row[1]} | {row[3]} | {row[4]}{reason}"
        )
    lines.extend(
        [
            "",
            (
                "Portée actuelle : correspondant + destinataire et politiques "
                "explicites. Les ressemblances de contenu restent des indices, "
                "jamais une règle automatique."
            ),
            "",
            "Commandes sûres :",
            "- envoie-moi la liste complète des règles",
            "- importe le CSV joint dans la liste blanche/noire",
            "- corrige F-12 en légitime/spam/suspect/dangereux/indéterminé",
            "- désactive F-12 ou P-1234abcd",
            "- restaure F-12 ou P-1234abcd",
            "",
            "Une désactivation est réversible et toutes les modifications sont auditées.",
            "",
            "— MAIA, SentiMail V3",
        ]
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "rule_id", "kind", "status", "decision", "match", "recipient",
            "subject", "updated_at", "reason_code", "user_reason",
        ]
    )
    writer.writerows([[csv_safe_cell(value) for value in row] for row in rows])
    return RuleResponse(
        "\n".join(lines),
        "regles-maia.csv",
        output.getvalue().encode("utf-8-sig"),
    )


async def apply_rule_request(
    pool: asyncpg.Pool[Any],
    participant: str,
    action: str,
    gate: RuleGate,
    *,
    raw_message: bytes | None = None,
) -> RuleResponse:
    if action == "list_rules":
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES "
                "('assistant','rulebook.exported',$1::jsonb)",
                _json({"participant": participant}),
            )
        return await render_rulebook(pool, participant)
    if action == "import_rules":
        if raw_message is None:
            return RuleResponse(
                "Je n’ai trouvé aucun message source contenant la pièce jointe. "
                "Aucune liste n’a été modifiée.\n\n— MAIA, SentiMail V3",
                applied=False,
            )
        try:
            reading = parse_policy_import(raw_message, gate.list_action)
            entries = reading.entries
        except RuleImportError as exc:
            return RuleResponse(
                f"Je n’ai importé aucune adresse : {exc}.\n\n"
                "Format attendu : un fichier UTF-8 CSV `email,liste` ou un TXT "
                "avec une adresse par ligne après avoir nommé la liste dans ta demande.\n\n"
                "— MAIA, SentiMail V3",
                applied=False,
            )
        counts = {"allow": 0, "hold": 0}
        async with pool.acquire() as connection, connection.transaction():
            for sender, list_action in entries:
                await set_sender_list_policy(
                    connection,
                    participant,
                    sender,
                    list_action,
                    source="authenticated_smtp_import",
                )
                counts[list_action] += 1
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES "
                "('assistant','rulebook.sender_lists_imported',$1::jsonb)",
                _json(
                    {
                        "participant": participant,
                        "allow_count": counts["allow"],
                        "hold_count": counts["hold"],
                        "entry_count": len(entries),
                    }
                ),
            )
        lines = [
            (
                f"Import terminé : {counts['allow']} adresse(s) en liste blanche"
                f" et {counts['hold']} en liste noire."
            )
        ]
        if reading.has_rejects:
            # Nommer ce qui a été écarté évite de tout recommencer à l'aveugle.
            lines.extend(
                [
                    "",
                    f"{len(reading.rejected)} ligne(s) n’ont pas été retenues :",
                    *[f"- {value}" for value in reading.rejected[:10]],
                ]
            )
            if len(reading.rejected) > 10:
                lines.append(f"- … et {len(reading.rejected) - 10} autre(s).")
            lines.append(
                "Corrige-les et renvoie-moi seulement celles-là : le reste est "
                "déjà enregistré."
            )
        lines.extend(
            [
                "",
                (
                    "Une adresse en liste blanche ne t’évite que le bruit "
                    "habituel de ce correspondant. Si je trouve une pièce jointe "
                    "dangereuse, un lien malveillant, une demande d’identifiants "
                    "ou une identité qui ne tient pas, je te demanderai quand "
                    "même ton avis : une adresse de confiance peut être "
                    "compromise."
                ),
                "",
                "— MAIA, SentiMail V3",
            ]
        )
        return RuleResponse("\n".join(lines))
    if action == "set_sender_rule":
        if gate.sender is None or gate.list_action not in LIST_ACTIONS:
            return RuleResponse(
                "Je n’ai modifié aucune liste : l’adresse ou la liste est ambiguë.\n\n"
                "— MAIA, SentiMail V3",
                applied=False,
            )
        async with pool.acquire() as connection, connection.transaction():
            await set_sender_list_policy(
                connection,
                participant,
                gate.sender,
                gate.list_action,
                source="authenticated_smtp_directive",
            )
            await connection.execute(
                "INSERT INTO audit_log(actor,action,payload) VALUES "
                "('assistant','rulebook.sender_list_changed',$1::jsonb)",
                _json(
                    {
                        "participant": participant,
                        "sender": gate.sender,
                        "list_action": gate.list_action,
                    }
                ),
            )
        list_name = "blanche" if gate.list_action == "allow" else "noire"
        return RuleResponse(
            f"{gate.sender} est maintenant en liste {list_name}. "
            "L’éventuelle entrée opposée a été désactivée.\n\n— MAIA, SentiMail V3"
        )
    if gate.rule_id is None:
        raise ValueError("validated rule request has no rule id")
    if gate.rule_id.startswith("F-"):
        return await _change_feedback(pool, participant, action, gate)
    return await _change_policy(pool, participant, action, gate)


async def _change_feedback(
    pool: asyncpg.Pool[Any], participant: str, action: str, gate: RuleGate
) -> RuleResponse:
    feedback_id = int(gate.rule_id.split("-", 1)[1])
    async with pool.acquire() as connection, connection.transaction():
        row = await connection.fetchrow(
            """
            SELECT l.id,l.label,l.active,
                   coalesce(l.sender_normalized, lower(m.envelope_from)) AS sender,
                   coalesce(l.subject, m.subject) AS subject
            FROM labels l LEFT JOIN messages m ON m.id=l.message_id
            WHERE l.id=$1 AND l.source='smtp_feedback_user'
              AND (
                  lower(l.participant_email)=lower($2)
                  OR (
                      l.participant_email IS NULL AND EXISTS (
                          SELECT 1 FROM unnest(m.envelope_recipients) recipient
                          WHERE lower(recipient)=lower($2)
                      )
                  )
              )
            FOR UPDATE OF l
            """,
            feedback_id,
            participant,
        )
        if row is None:
            return RuleResponse(f"La règle {gate.rule_id} n’existe pas pour cet utilisateur.")
        before = {"label": row["label"], "active": row["active"]}
        label = gate.classification if action == "update_rule" else str(row["label"])
        active = action != "disable_rule" if action != "update_rule" else True
        await connection.execute(
            "UPDATE labels SET label=$2,active=$3,updated_at=now() WHERE id=$1",
            feedback_id,
            label,
            active,
        )
        after = {"label": label, "active": active}
        await connection.execute(
            "INSERT INTO audit_log(actor,action,payload) VALUES "
            "('assistant','rulebook.feedback_changed',$1::jsonb)",
            _json(
                {
                    "participant": participant,
                    "rule_id": gate.rule_id,
                    "operation": action,
                    "before": before,
                    "after": after,
                }
            ),
        )
    sender = str(row["sender"] or "adresse effacée")
    state = "active" if active else "disabled"
    return RuleResponse(
        f"Règle {gate.rule_id} mise à jour : {label}, {state}.\n"
        f"Correspondant : {sender}\nObjet témoin : {row['subject'] or '(sans objet)'}\n\n"
        "La modification est auditée et réversible.\n\n— MAIA, SentiMail V3"
    )


async def _change_policy(
    pool: asyncpg.Pool[Any], participant: str, action: str, gate: RuleGate
) -> RuleResponse:
    if action == "update_rule":
        return RuleResponse(
            "Une politique d’expéditeur ne peut pas changer de cible en place. "
            "Désactive-la, puis indique à MAIA la nouvelle politique souhaitée."
        )
    prefix = gate.rule_id.split("-", 1)[1].casefold()
    async with pool.acquire() as connection, connection.transaction():
        matches = await connection.fetch(
            """
            SELECT id,scope,value_normalized,action,active
            FROM sender_policies
            WHERE lower(participant_email)=lower($1)
              AND replace(id::text,'-','') LIKE $2 || '%'
            FOR UPDATE
            """,
            participant,
            prefix.replace("-", ""),
        )
        if len(matches) != 1:
            return RuleResponse(
                f"La règle {gate.rule_id} est introuvable ou ambiguë pour cet utilisateur."
            )
        row = matches[0]
        active = action == "restore_rule"
        await connection.execute(
            "UPDATE sender_policies SET active=$2,updated_at=now() WHERE id=$1",
            row["id"],
            active,
        )
        await connection.execute(
            "INSERT INTO audit_log(actor,action,payload) VALUES "
            "('assistant','rulebook.policy_changed',$1::jsonb)",
            _json(
                {
                    "participant": participant,
                    "rule_id": gate.rule_id,
                    "operation": action,
                    "before": {"active": row["active"]},
                    "after": {"active": active},
                }
            ),
        )
    state = "active" if active else "disabled"
    return RuleResponse(
        f"Règle {gate.rule_id} {state} : {row['scope']}={row['value_normalized']} "
        f"({row['action']}).\n\nLa modification est auditée et réversible.\n\n"
        "— MAIA, SentiMail V3"
    )
