"""Ce qu'un destinataire a choisi de recevoir de MAIA.

Deux réglages de `participant_preferences`, posés par l'opérateur à la
demande du destinataire (décision du mainteneur du 15 octobre 2026, pour une
destinataire qui recevait seize avis par mois, dont neuf sans danger) :

- `ask_only_on_real_doubt` : ne l'interroger que sur un vrai doute, c'est-à-dire
  une preuve matérielle de danger, une convergence défavorable, une retenue
  qu'il a lui-même posée, une pièce jointe que rien n'a pu ouvrir, ou un
  verdict dangereux. Le reste lui est livré : un message laissé passer n'est
  pas grave pour lui, une question de trop l'est ;
- `hold_reminders_enabled` : faux, un message retenu n'est jamais relancé. Le
  premier avis est le seul ; sans réponse, le dossier est abandonné à
  l'échéance, sans courrier.

Absents, les deux valent comme pour tout le monde : chaque doute est une
question, chaque retenue oubliée est relancée une fois.
"""

from __future__ import annotations

from typing import Any

ASK_ONLY_ON_REAL_DOUBT = "ask_only_on_real_doubt"
HOLD_REMINDERS = "hold_reminders_enabled"


async def asks_only_on_real_doubt(pool: Any, recipients: list[str]) -> bool:
    """Vrai seulement pour un message adressé à ce seul destinataire.

    Le choix d'un destinataire ne gouverne jamais le verdict d'un autre : un
    message à plusieurs destinataires garde ses questions. Le MX sépare
    aujourd'hui chaque destinataire ; la garde tient si cela change.
    """
    if len(recipients) != 1 or not recipients[0]:
        return False
    participant = str(recipients[0])
    value = await pool.fetchval(
        """
        SELECT (value)::text::boolean FROM participant_preferences
        WHERE participant_email=lower($1) AND name=$2
        """,
        participant,
        ASK_ONLY_ON_REAL_DOUBT,
    )
    return bool(value)
