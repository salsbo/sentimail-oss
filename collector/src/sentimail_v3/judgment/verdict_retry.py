"""Quand le juge réessaie un dossier après un échec.

Nuit du 15 octobre 2026 : l'API du modèle répondait `HTTP 200` puis ne
terminait plus sa réponse, de 1 h à 5 h UTC. Les trois essais d'un dossier
s'enchaînaient en 37 minutes, tous pendant la même lenteur, puis le dossier
partait à l'humain. Un essai repris aussitôt après une panne passagère
retombe dans la même panne.

Un échec passager du modèle planifie donc le nouvel essai 15 minutes, puis
1 heure, puis 4 heures plus tard : quatre essais au total, l'escalade humaine
après l'échec du quatrième. L'échéance est écrite en base
(`verdict_runs.next_attempt_at`) : elle survit à un redémarrage.

Les autres erreurs gardent leur cadence historique : trois essais espacés de
quinze secondes par essai déjà fait, puis l'escalade. Un refus de crédit
(`HTTP 402`) en fait partie : c'est un état du compte, pas une lenteur, et le
superviseur doit le dire tout de suite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta

from sentimail_v3.llm import LlmError

# Cadence historique, inchangée pour toute erreur qui n'est pas passagère.
MAX_ATTEMPTS = 3
# Attente avant le 2e, le 3e puis le 4e essai, après un échec passager.
TRANSIENT_RETRY_DELAYS = (
    timedelta(minutes=15),
    timedelta(hours=1),
    timedelta(hours=4),
)
MAX_TRANSIENT_ATTEMPTS = 1 + len(TRANSIENT_RETRY_DELAYS)
# La contrainte de la table (attempts BETWEEN 0 AND 10). Un run qui
# l'atteindrait par des redémarrages répétés n'est plus repris : le
# superviseur le voit en retard, au lieu d'une erreur de contrainte qui
# arrêterait le juge.
ATTEMPTS_CEILING = 10
# Retard toléré sur une échéance avant de la dire manquée. Un essai dû attend
# qu'un juge se libère : deux juges, et pendant la panne du 15 octobre un
# essai durait jusqu'à 12 min (analyse profonde puis 120 s d'appel). Quinze
# minutes couvrent cet essai le plus long, plus la boucle de cinq secondes.
RETRY_GRACE = timedelta(minutes=15)

# Messages de LlmError qui disent une configuration, jamais une lenteur.
# Tenus à jour avec llm.py par un test.
CONFIGURATION_FAILURES = (
    "aucun fournisseur LLM n'est configuré",
    "fichier de secret fournisseur refusé",
    "aucune adresse de modèle local configurée",
)
_HTTP_STATUS = re.compile(r"\bHTTP (\d{3})\b")
# Codes qui disent « réessaie plus tard ». Les autres 4xx disent une requête,
# une clé ou un compte à corriger : attendre ne les répare pas.
_RETRYABLE_HTTP = frozenset({408, 409, 425, 429})


@dataclass(frozen=True)
class RetryPlan:
    """Ce qui suit un échec : `scheduled`, `immediate` ou `exhausted`."""

    kind: str
    delay: timedelta | None = None

    @property
    def exhausted(self) -> bool:
        return self.kind == "exhausted"


def is_transient(exc: BaseException) -> bool:
    """Un échec du modèle qu'une attente peut résoudre."""
    if not isinstance(exc, LlmError):
        return False
    message = str(exc)
    status = _HTTP_STATUS.search(message)
    if status:
        code = int(status.group(1))
        return code >= 500 or code in _RETRYABLE_HTTP
    return not any(marque in message for marque in CONFIGURATION_FAILURES)


def plan_retry(attempts: int, exc: BaseException) -> RetryPlan:
    """Le sort d'un run après l'échec de son essai numéro `attempts`."""
    if is_transient(exc):
        if attempts < MAX_TRANSIENT_ATTEMPTS:
            return RetryPlan("scheduled", TRANSIENT_RETRY_DELAYS[max(attempts, 1) - 1])
        return RetryPlan("exhausted")
    if attempts >= MAX_ATTEMPTS:
        return RetryPlan("exhausted")
    return RetryPlan("immediate")


_GRACE_SQL = f"interval '{int(RETRY_GRACE.total_seconds())} seconds'"

# Le dernier run du juge pour ce message, avec son échéance s'il en a une.
# Un run reste `error` sans date de fin tant qu'un essai reste à venir ;
# `next_attempt_at` garde l'échéance de l'essai planifié pendant qu'il tourne.
_LATEST_RUN = """(
        SELECT vr.status, vr.completed_at, vr.next_attempt_at, vr.started_at
        FROM verdict_runs vr JOIN investigations i ON i.id=vr.investigation_id
        WHERE i.message_id={message}.id
        ORDER BY vr.started_at DESC NULLS LAST LIMIT 1
    )"""


def retry_on_schedule_sql(message: str = "m") -> str:
    """Vrai quand le message attend un essai planifié, ou l'exécute, dans les temps.

    Rien n'y est immobilisé : le dossier attend une échéance choisie.
    """
    return f"""EXISTS (
    SELECT 1 FROM {_LATEST_RUN.format(message=message)} dernier
    WHERE dernier.next_attempt_at IS NOT NULL AND (
        (dernier.status='error' AND dernier.completed_at IS NULL
         AND dernier.next_attempt_at > now() - {_GRACE_SQL})
        OR (dernier.status='running' AND dernier.started_at > now() - {_GRACE_SQL})
    )
)"""


def retry_overdue_sql(message: str = "m") -> str:
    """Vrai quand l'essai planifié du message a manqué son échéance.

    Échéance dépassée de plus de `RETRY_GRACE` sans que l'essai démarre, ou
    essai planifié démarré depuis plus longtemps sans aboutir.
    """
    return f"""EXISTS (
    SELECT 1 FROM {_LATEST_RUN.format(message=message)} dernier
    WHERE dernier.next_attempt_at IS NOT NULL AND (
        (dernier.status='error' AND dernier.completed_at IS NULL
         AND dernier.next_attempt_at <= now() - {_GRACE_SQL})
        OR (dernier.status='running' AND dernier.started_at <= now() - {_GRACE_SQL})
    )
)"""


# Un run en erreur qui attend son échéance dans les temps : pas un échec acquis.
# Le coalesce rend faux, jamais NULL, un run sans échéance : sous un NOT, un
# NULL écarterait aussi les erreurs historiques qu'on doit continuer à compter.
WAITING_RUN_SQL = (
    "(completed_at IS NULL AND "
    f"coalesce(next_attempt_at > now() - {_GRACE_SQL}, false))"
)
