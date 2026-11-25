"""L'agent d'entretien : il regarde le système, diagnostique, et répare borné.

Régulièrement, il rassemble ce qui ne va pas - verdicts en erreur, livraisons
différées, dossiers coincés, désaccords entre les qualifications humaines et
les verdicts, alertes récentes - et demande un diagnostic à un modèle, Claude
de préférence.

Ce qu'il peut corriger est écrit ici, dans une liste fermée d'actions sûres,
idempotentes et bornées : rejouer un verdict échoué, relancer une livraison
différée, réconcilier une retenue sans avis. Le modèle recommande, le code
n'exécute que ce qu'il connaît - une recommandation inconnue est rapportée à
l'exploitant, jamais improvisée. Ni code, ni configuration, ni règle de
détection ne se modifient par cette voie : un agent qui s'auto-corrigerait
sans borne serait lui-même la panne à craindre.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import asyncpg
import httpx

from sentimail_v3.code.doctrine_learning import refresh_learned_doctrine
from sentimail_v3.code.reference import nommer_dossier
from sentimail_v3.config import Settings, load_settings
from sentimail_v3.conversation.conversation import ConversationStore
from sentimail_v3.crypto import load_key
from sentimail_v3.execution.delivery import retry_one_release
from sentimail_v3.execution.delivery_state import TERMINAL
from sentimail_v3.execution.review_guard import reconcile_one_review_hold
from sentimail_v3.identity import instance_identity
from sentimail_v3.judgment.verdict_engine import PROMPT_VERSION
from sentimail_v3.judgment.verdict_retry import (
    MAX_ATTEMPTS,
    WAITING_RUN_SQL,
    retry_on_schedule_sql,
)
from sentimail_v3.llm import LlmError, provider_chat_json
from sentimail_v3.llm_accounting import llm_scope, observed_call
from sentimail_v3.supervision import discrepancies
from sentimail_v3.supervision.evaluation_report import publish as publish_evaluation
from sentimail_v3.supervision.health import pulse

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3-caretaker")

# Les seules actions que l'agent sait exécuter. Fermée par construction.
SAFE_ACTIONS = (
    "replay_errored_verdicts",
    "retry_deferred_deliveries",
    "reconcile_review_holds",
    "none",
)
MAX_REPLAYS_PER_RUN = 5

SYSTEM = """Tu es l'agent d'entretien de SentiMail V3, un filtre de courrier.
On te donne un état de santé : erreurs, retards, désaccords, alertes. Réponds
par un unique objet JSON :
{
  "diagnosis": "une synthèse en français, deux phrases",
  "suspected_causes": ["..."],
  "recommended_actions": ["replay_errored_verdicts|retry_deferred_deliveries|reconcile_review_holds|none"],
  "needs_operator": true,
  "operator_note": "ce que l'exploitant doit savoir ou faire, sinon null"
}
Ne recommande une action que si l'état la justifie. Tout ce que tu écris hors
de ces champs est ignoré ; toute action hors de la liste est ignorée.

sens_des_desaccords_7j sépare deux défauts opposés, et c'est le champ à lire :
demande_au_lieu_de_classer compte les indésirables soumis à l'humain,
demande_au_lieu_de_livrer les messages ordinaires soumis à l'humain. Ne
recommande jamais d'ajuster un seuil de classification à partir de leur somme :
tout seuil qui corrige l'un aggrave l'autre. Quand les deux sont élevés, la
cause n'est pas un seuil mais un manque d'indices pour trancher - dis-le.
erreur_de_qualification et laisse_passer désignent, eux, de vraies erreurs.
Tout désaccord est déjà tranché par le verdict humain, qui s'applique : ne
demande jamais à l'exploitant de revoir, d'examiner ou d'acquitter un écart
ni un dossier qualifié par un destinataire.

Un refus SMTP définitif « destinataire inconnu » n'appelle aucune correction :
le dossier est conclu, et créer la boîte devinée par un expéditeur de masse
serait lui ouvrir une porte. Ne le signale pas comme une anomalie à traiter."""


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    logger.info(_json({"event": event, **fields}))


async def collect(pool: asyncpg.Pool[Any]) -> dict[str, Any]:
    """L'état de santé factuel, sans interprétation."""
    # Un dossier qui attend, dans les temps, l'essai planifié après une panne
    # passagère du modèle n'est ni coincé ni en échec : il attend une échéance
    # choisie. Le 15 octobre 2026, trois essais enchaînés pendant la même
    # lenteur ont fait écrire « intervention requise » pour une attente.
    # Une échéance manquée, elle, le refait compter dans les deux.
    row = await pool.fetchrow(
        """
        SELECT
          (SELECT count(*) FROM verdict_runs
            WHERE status='error' AND created_at > now()-interval '24 hours'
              AND NOT """ + WAITING_RUN_SQL + """)
            AS verdicts_en_erreur_24h,
          (SELECT count(*) FROM messages
            WHERE delivery_status='deferred') AS livraisons_differees,
          (SELECT count(*) FROM messages m
            WHERE m.delivery_status IN ('captured','analyzing')
              AND m.captured_at < now()-interval '30 minutes'
              AND NOT """ + retry_on_schedule_sql("m") + """) AS dossiers_coinces,
          -- « ignored » est un état voulu : le dossier a été abandonné faute
          -- de réponse, décision prise et tracée. Le compter ici ferait passer
          -- dix-huit abandons pour dix-huit incidents, et noierait le seul cas
          -- qui en est un : un message retenu dont l'avis n'est jamais parti.
          (SELECT count(*) FROM messages m JOIN delivery_cases dc
             ON dc.message_id=m.id
            WHERE m.delivery_status='held'
              AND dc.state NOT IN
                ('review_notice_pending','awaiting_reply','closed','ignored'))
            AS retenues_sans_avis,
          (SELECT count(*) FROM audit_log
            WHERE action='operational.alert_suppressed'
              AND created_at > now()-interval '24 hours') AS alertes_amorties_24h
        """
    )
    disagreements = await pool.fetch(
        """
        SELECT l.label AS humain, vr.response->'verdict'->>'classification'
                 AS modele, count(*)
        FROM labels l
        JOIN investigations i ON i.message_id=l.message_id
        JOIN verdict_runs vr ON vr.investigation_id=i.id AND vr.status='complete'
        WHERE l.active AND l.created_at > now()-interval '7 days'
          AND l.label <> vr.response->'verdict'->>'classification'
          -- Seule la version de prompt déployée décrit le système actuel. Les
          -- désaccords d'une version retirée traînaient sept jours durant et
          -- faisaient recommander des réglages pour un moteur qui n'existe plus.
          AND vr.prompt_version = $1
        GROUP BY 1,2 ORDER BY 3 DESC LIMIT 6
        """,
        PROMPT_VERSION,
    )
    errors = await pool.fetch(
        """
        SELECT error_type, left(error_detail,120) AS detail, count(*)
        FROM verdict_runs
        WHERE status='error' AND created_at > now()-interval '24 hours'
          AND NOT """ + WAITING_RUN_SQL + """
        GROUP BY 1,2 ORDER BY 3 DESC LIMIT 5
        """
    )
    ecarts = [dict(value) for value in disagreements]
    return {
        **dict(row),
        "prompt_actif": PROMPT_VERSION,
        "desaccords_humain_modele_7j": ecarts,
        # Le détail par sens, sans lequel le total appelle un réglage de seuil
        # qui aggraverait forcément l'un des deux défauts.
        "sens_des_desaccords_7j": disagreement_directions(ecarts),
        "erreurs_de_verdict_24h": [dict(value) for value in errors],
    }


# Les issues qui laissent la décision à l'humain. Un désaccord avec l'une
# d'elles ne dit pas que le modèle s'est trompé : il dit qu'il n'a pas su.
_UNDECIDED = frozenset({"suspect", "undetermined"})
_ADVERSE = frozenset({"spam", "dangerous", "suspect"})


def disagreement_directions(
    disagreements: list[dict[str, object]]
) -> dict[str, int]:
    """Range les désaccords par SENS, car ils ne se compensent pas.

    « Il m'a demandé pour un indésirable » et « il m'a demandé pour un message
    ordinaire » sont deux défauts opposés. Les additionner produit un chiffre
    qui appelle un réglage de seuil - or tout seuil qui corrige l'un aggrave
    l'autre. Séparés, ils disent la vraie cause : le modèle manque d'indices
    pour trancher, dans les deux sens.
    """
    lecture = {
        "demande_au_lieu_de_classer": 0,
        "demande_au_lieu_de_livrer": 0,
        "erreur_de_qualification": 0,
        "laisse_passer": 0,
    }
    for value in disagreements:
        humain = str(value.get("humain") or "")
        modele = str(value.get("modele") or "")
        compte = int(value.get("count") or 0)
        if modele in _UNDECIDED and humain in _ADVERSE:
            lecture["demande_au_lieu_de_classer"] += compte
        elif modele in _UNDECIDED and humain == "legitimate":
            lecture["demande_au_lieu_de_livrer"] += compte
        elif humain == "legitimate" and modele in {"spam", "dangerous"}:
            lecture["erreur_de_qualification"] += compte
        elif humain in _ADVERSE and modele == "legitimate":
            lecture["laisse_passer"] += compte
    return lecture


def _actionable_verdict_errors(state: dict[str, Any]) -> int:
    """Les erreurs de verdict sur lesquelles quelqu'un peut agir.

    Un refus définitif du relais - « destinataire inconnu » - n'en fait pas
    partie : le dossier a été conclu, il n'y a rien à réparer, et la seule
    « correction » imaginable serait de créer la boîte que le spammeur a
    devinée. Le rapporter ferait donc recommander l'ouverture d'une porte.
    """
    errors = state.get("erreurs_de_verdict_24h")
    if not isinstance(errors, list) or not errors:
        return int(state.get("verdicts_en_erreur_24h") or 0)
    actionable = 0
    for entry in errors:
        if not isinstance(entry, dict):
            continue
        detail = str(entry.get("detail") or "").casefold()
        definitif = "5.1.1" in detail or "user unknown" in detail
        if not definitif:
            actionable += int(entry.get("count") or 0)
    return actionable


def report_fingerprint(state: dict[str, Any]) -> str:
    """L'empreinte de ce que le rapport raconte, hors bruit d'horodatage.

    Six déploiements successifs ont redémarré l'entretien le 20/08 au soir, et
    chaque démarrage renvoyait le même « signalement faible ». Ce que le
    rapport raconte tient dans ces clés : tant qu'elles ne bougent pas, un
    nouveau courrier ne dirait rien de plus.
    """
    vue = {
        key: state.get(key)
        for key in (
            "retenues_sans_avis",
            "dossiers_coinces",
            "livraisons_differees",
            "alertes_amorties_24h",
            "verdicts_en_erreur_24h",
            "erreurs_de_verdict_24h",
            "sens_des_desaccords_7j",
            "desaccords_humain_modele_7j",
        )
    }
    return hashlib.sha256(
        json.dumps(vue, ensure_ascii=False, sort_keys=True, default=str).encode()
    ).hexdigest()


def worth_reporting(state: dict[str, Any]) -> bool:
    """Quelque chose mérite l'attention du cycle - pas forcément un courrier."""
    if _actionable_verdict_errors(state) > 0:
        return True
    return any(
        int(state.get(key) or 0) > 0
        for key in (
            "livraisons_differees",
            "dossiers_coinces",
            "retenues_sans_avis",
        )
    ) or bool(state.get("desaccords_humain_modele_7j"))


def actionable_signals(state: dict[str, Any]) -> bool:
    """Un geste de réparation est peut-être justifié : le diagnostic a un sens.

    Les désaccords, eux, ne se réparent pas par une action de la liste : les
    diagnostiquer à chaque cycle coûtait un appel au modèle pour conclure
    « rien à faire ».
    """
    if _actionable_verdict_errors(state) > 0:
        return True
    return any(
        int(state.get(key) or 0) > 0
        for key in ("livraisons_differees", "dossiers_coinces", "retenues_sans_avis")
    )


def mail_worthy(state: dict[str, Any]) -> bool:
    """Un courrier ne part que pour une anomalie d'exploitation levée.

    Un désaccord humain/modèle n'en est jamais une : le verdict humain s'est
    appliqué, personne ne repasse derrière (règle du 13 septembre 2026). Les
    écarts restent mesurés sur la page de la console, sans courrier.
    """
    return any(
        int(state.get(key) or 0) > 0
        for key in (
            "retenues_sans_avis",
            "dossiers_coinces",
            "livraisons_differees",
        )
    )


async def _anthropic_diagnose(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    api_key: str,
    model: str,
    state: dict[str, Any],
) -> str:
    async def invoke() -> tuple[str, dict[str, Any]]:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
            json={
                "model": model,
                "system": SYSTEM,
                "messages": [
                    {"role": "user", "content": "ÉTAT:\n" + _json(state)}
                ],
                "max_tokens": 800,
            },
            timeout=120.0,
        )
        response.raise_for_status()
        payload = response.json()
        text = "".join(
            str(block.get("text") or "")
            for block in payload.get("content") or []
            if isinstance(block, dict) and block.get("type") == "text"
        )
        return text, {
            "http_status": response.status_code,
            "usage": payload.get("usage") if isinstance(payload, dict) else {},
        }

    with llm_scope(purpose="caretaker"):
        content, _ = await observed_call(
            pool,
            role="caretaker",
            provider="anthropic",
            model=model,
            invoke=invoke,
        )
    return content


async def diagnose(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    state: dict[str, Any],
) -> dict[str, Any]:
    """Le diagnostic du modèle, Claude en préférence, fail-soft sinon.

    Sans modèle joignable, l'agent ne devine pas : il rapporte les faits bruts
    à l'exploitant et n'exécute que ce que les faits imposent d'évidence.
    """
    anthropic_key = ""
    key_path = Path(settings.provider_secrets_dir) / "anthropic_api_key"
    if key_path.exists():
        anthropic_key = key_path.read_text(encoding="utf-8").strip()
    try:
        if anthropic_key:
            content = await _anthropic_diagnose(
                pool, client, anthropic_key, settings.anthropic_model, state
            )
        else:
            content, _ = await provider_chat_json(
                pool,
                client,
                settings,
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": "ÉTAT:\n" + _json(state)},
                ],
                max_tokens=800,
            )
    except (LlmError, httpx.HTTPError) as exc:
        return {
            "diagnosis": "Diagnostic indisponible : aucun modèle joignable.",
            "suspected_causes": [f"{type(exc).__name__}"],
            "recommended_actions": [],
            "needs_operator": True,
            "operator_note": "L'agent d'entretien n'a pas pu joindre de modèle.",
        }
    start, end = content.find("{"), content.rfind("}")
    try:
        value = json.loads(content[start : end + 1])
    except (ValueError, TypeError):
        value = {}
    actions = [
        str(action)
        for action in (value.get("recommended_actions") or [])
        if str(action) in SAFE_ACTIONS
    ]
    return {
        "diagnosis": str(value.get("diagnosis") or "")[:1200],
        "suspected_causes": [
            str(cause)[:200] for cause in (value.get("suspected_causes") or [])[:6]
        ],
        "recommended_actions": actions,
        "ignored_recommendations": [
            str(action)
            for action in (value.get("recommended_actions") or [])
            if str(action) not in SAFE_ACTIONS
        ][:6],
        "needs_operator": bool(value.get("needs_operator")),
        "operator_note": (
            str(value["operator_note"])[:1000]
            if value.get("operator_note")
            else None
        ),
    }


async def _replay_errored(pool: asyncpg.Pool[Any], settings: Settings) -> int:
    """Rejoue les verdicts épuisés en erreur, sans jamais toucher un livré.

    Épuisé veut dire daté de fin. Un troisième échec passager attend encore
    son quatrième essai, à quatre heures : le rejouer supprimerait son run et
    relancerait le dossier aussitôt, dans la panne qu'on laisse passer.
    """
    rows = await pool.fetch(
        """
        SELECT DISTINCT i.message_id::text AS message_id
        FROM verdict_runs vr
        JOIN investigations i ON i.id=vr.investigation_id
        JOIN messages m ON m.id=i.message_id
        WHERE vr.status='error' AND vr.attempts >= $3
          AND vr.completed_at IS NOT NULL
          AND vr.created_at > now()-interval '24 hours'
          AND NOT (m.delivery_status = ANY($2::text[]))
        LIMIT $1
        """,
        MAX_REPLAYS_PER_RUN,
        sorted(TERMINAL),
        MAX_ATTEMPTS,
    )
    from sentimail_v3.supervision.replay import replay_case

    done = 0
    for row in rows:
        try:
            await replay_case(
                pool,
                str(row["message_id"]),
                fresh_evidence=False,
                # Sans la clé, un message chiffré au repos est rejouable par
                # la CLI mais pas par l'agent : chaque cycle échouait en
                # DecryptionError silencieuse.
                encryption_key=load_key(settings.raw_eml_key_file),
            )
            done += 1
        except Exception as exc:  # noqa: BLE001 - un rejeu raté n'arrête pas les autres
            _log("caretaker.replay_failed", message_id=row["message_id"],
                 error=type(exc).__name__)
    return done


async def _invitation_queue(
    pool: asyncpg.Pool[Any], settings: Settings
) -> ConversationStore:
    """La file qui remet un avis MAIA en route, la même que celle du verdict.

    Réparer une retenue orpheline, c'est recréer l'avis qui lui manque : il
    faut donc pouvoir le mettre en file. Depuis que la réparation l'exige,
    l'action du caretaker l'appelait sans, et échouait en TypeError à chaque
    passage - le journal disait « caretaker.error » et rien n'était réparé.
    """
    identite = await instance_identity(pool, settings)
    return ConversationStore(
        pool,
        identite.action_address,
        identite.assistant_sender,
        settings.render_sandbox_url,
        identite.action_aliases,
        load_key(settings.raw_eml_key_file),
        settings=settings,
    )


async def execute(
    pool: asyncpg.Pool[Any], settings: Settings, actions: list[str]
) -> dict[str, int]:
    """Exécute les actions recommandées - et seulement celles de la liste."""
    outcome: dict[str, int] = {}
    for action in actions:
        if action == "replay_errored_verdicts":
            outcome[action] = await _replay_errored(pool, settings)
        elif action == "retry_deferred_deliveries":
            done = 0
            for _ in range(10):
                if not await retry_one_release(pool, settings):
                    break
                done += 1
            outcome[action] = done
        elif action == "reconcile_review_holds":
            invitations = await _invitation_queue(pool, settings)
            done = 0
            for _ in range(10):
                if not await reconcile_one_review_hold(pool, settings, invitations):
                    break
                done += 1
            outcome[action] = done
    return outcome


async def report(
    pool: asyncpg.Pool[Any],
    settings: Settings,
    state: dict[str, Any],
    verdict: dict[str, Any],
    outcome: dict[str, int],
) -> None:
    from sentimail_v3.execution.outbox import queue_response
    from sentimail_v3.supervision.caretaker_letter import lettre

    # L'état sort en clés de base : le mettre tel quel dans une lettre suppose
    # que le lecteur sache ce qu'est une « retenue sans avis », et pourquoi
    # zéro y est une bonne nouvelle. La traduction se fait ici, une fois, sans
    # rien retirer - l'état brut reste en fin de lettre pour l'audit.
    ecarts_url = f"{settings.console_url}/ecarts" if settings.console_url else None
    rendu = lettre(state, verdict, outcome, ecarts_url=ecarts_url)
    identite = await instance_identity(pool, settings)
    # Un fil par exploitant : une conversation partagée rattacherait la réponse
    # de l'un au fil de l'autre, et le rapport serait lu comme une réponse à
    # une question qui n'a pas été posée.
    async with pool.acquire() as connection, connection.transaction():
        for destinataire in settings.operator_addresses:
            conversation_id = await connection.fetchval(
                """
                INSERT INTO conversations (participant_email, status)
                VALUES ($1,'awaiting_user') RETURNING id::text
                """,
                destinataire,
            )
            await queue_response(
                connection,
                str(conversation_id),
                None,
                destinataire,
                identite.assistant_sender,
                identite.action_address,
                rendu.subject,
                rendu.text,
                body_html=rendu.html,
            )


async def run_once(pool: asyncpg.Pool[Any], settings: Settings) -> dict[str, Any]:
    # Les écarts s'enregistrent avant la photographie de l'état, pour que le
    # cycle qui découvre un désaccord soit aussi celui qui le compte ouvert.
    fresh = await discrepancies.record(pool, PROMPT_VERSION)
    if fresh:
        _log("caretaker.discrepancies_recorded", count=fresh)
    state = await collect(pool)
    if not worth_reporting(state):
        _log("caretaker.all_clear", **{k: v for k, v in state.items()
                                       if isinstance(v, int)})
        return {"state": state, "actions": {}}
    # Un état inchangé depuis le dernier rapport de l'intervalle ne mérite ni
    # un second courrier ni un diagnostic : chaque redémarrage relançait les
    # deux, et le destinataire recevait le même « signalement faible ».
    empreinte = report_fingerprint(state)
    precedente = await pool.fetchval(
        """
        SELECT payload->>'fingerprint' FROM audit_log
        WHERE action='caretaker.run'
          AND created_at > now() - ($1 * interval '1 hour')
        ORDER BY created_at DESC LIMIT 1
        """,
        settings.caretaker_interval_hours,
    )
    if precedente == empreinte:
        _log("caretaker.report_unchanged")
        return {"state": state, "actions": {}, "unchanged": True}
    if actionable_signals(state) or mail_worthy(state):
        # Sans timeout explicite, httpx coupe la lecture à 5 s : le diagnostic
        # LLM en prend souvent davantage, les en-têtes arrivaient (200 au
        # journal) puis le corps expirait, et chaque rapport concluait « aucun
        # modèle joignable » alors que le modèle répondait.
        async with httpx.AsyncClient(
            timeout=settings.deepseek_timeout_seconds
        ) as client:
            verdict = await diagnose(pool, client, settings, state)
        outcome = await execute(pool, settings, verdict["recommended_actions"])
    else:
        # Des prudences seules : rien à réparer, rien à envoyer. Demander un
        # diagnostic coûtait un appel au modèle pour conclure « rien à faire ».
        verdict = {
            "diagnosis": "",
            "suspected_causes": [],
            "recommended_actions": [],
            "ignored_recommendations": [],
            "needs_operator": False,
            "operator_note": None,
        }
        outcome = {}
    envoi = mail_worthy(state)
    await pool.execute(
        "INSERT INTO audit_log(actor,action,payload) VALUES "
        "('caretaker','caretaker.run',$1::jsonb)",
        _json({"state": state, "verdict": verdict, "outcome": outcome,
               "fingerprint": empreinte, "mailed": envoi}),
    )
    if envoi:
        await report(pool, settings, state, verdict, outcome)
    _log("caretaker.run", actions=outcome, mailed=envoi,
         needs_operator=verdict["needs_operator"])
    return {"state": state, "verdict": verdict, "actions": outcome}


async def main() -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    _log("worker.started", component="caretaker")
    while True:
        pulse("caretaker")
        try:
            await run_once(pool, settings)
        except Exception as exc:  # noqa: BLE001 - l'entretien survit à ses pannes
            _log("caretaker.error", error=type(exc).__name__, detail=str(exc)[:300])
        # La doctrine apprise se rafraîchit à chaque cycle, sans dépendre d'une
        # recommandation : ce qui s'apprend des qualifications humaines ne doit
        # pas attendre qu'un modèle veuille bien le demander.
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                written = await refresh_learned_doctrine(
                    pool,
                    client=client if settings.knowledge_embedding_url else None,
                    base_url=settings.knowledge_embedding_url,
                    model=settings.knowledge_embedding_model,
                )
            if written:
                _log("caretaker.doctrine_refreshed", notes=written)
        except Exception as exc:  # noqa: BLE001 - apprendre n'est jamais critique
            _log(
                "caretaker.doctrine_error",
                error=type(exc).__name__,
                detail=str(exc)[:300],
            )
        # Mesurer l'efficacité n'est jamais critique : le rapport se publie
        # après les actions correctives, et son échec ne les empêche pas.
        try:
            rapport = await publish_evaluation(pool)
            _log(
                "caretaker.evaluation",
                messages=rapport["matrix"]["total"],
                qualifies=sum(
                    ligne["labelled"] for ligne in rapport["matrix"]["rows"].values()
                ),
                utilite=rapport["utility"]["normalised"],
            )
        except Exception as exc:  # noqa: BLE001 - mesurer n'est jamais critique
            _log(
                "caretaker.evaluation_error",
                error=type(exc).__name__,
                detail=str(exc)[:300],
            )
        pulse("caretaker")
        try:
            from sentimail_v3.supervision.classifier_cycle import run_once as classifier_cycle
            result = await classifier_cycle(pool)
            _log("caretaker.classifier_cycle", result=result)
        except Exception as exc:  # noqa: BLE001 - aucun effet sur la livraison
            _log("caretaker.classifier_cycle_error", error=type(exc).__name__)
        await asyncio.sleep(settings.caretaker_interval_hours * 3600)


if __name__ == "__main__":
    asyncio.run(main())
