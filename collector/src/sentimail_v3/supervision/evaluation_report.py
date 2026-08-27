"""Rassembler ce qui s'est passé, et le publier là où l'état se lit déjà.

Le calcul vit dans `evaluation`, qui ne connaît ni base ni réseau. Ici on va
chercher les lignes, on assemble le rapport, et on le pose dans
`operational_status` sous son propre composant - la console d'administration
lit déjà cette table pour la page d'état, et n'a pas le droit d'importer le
collector.

Deux précautions qui tiennent tout le reste.

**L'issue se reconstruit depuis les événements de livraison.** Le champ
`original_delivery_allowed` du dossier est mis à jour après la réponse de
l'utilisateur : il raconte l'état final, pas la décision du moment. Une mesure
bâtie dessus compterait un message retenu puis libéré comme livré d'emblée, et
afficherait un taux de sollicitation nul. Les événements, eux, ne se
réécrivent pas.

**La mesure ne dégrade jamais l'état.** Un taux d'erreur élevé est une
information de qualité, pas une panne : le publier en « degraded » ferait
sonner l'alerte du superviseur pour quelque chose qui n'appelle aucune
intervention immédiate.
"""

from __future__ import annotations

import json
from typing import Any

import asyncpg

from sentimail_v3.supervision.evaluation import (
    confusion_matrix,
    generalized_risk,
    hold_precision,
    labelling_coverage,
    lam_percent,
    trec_rates,
    utility_score,
)

COMPONENT = "evaluation"
DEFAULT_WINDOW_DAYS = 30

# L'issue vient des événements, la vérité de l'utilisateur seul. Un message
# peut porter plusieurs labels au fil du temps ; le dernier qualifié fait foi,
# c'est le dernier avis que l'utilisateur a exprimé.
_ROWS_SQL = """
SELECT
  CASE
    WHEN EXISTS (
      SELECT 1 FROM delivery_events de
      WHERE de.case_id = dc.id AND de.event_type = 'original_filed_as_junk'
    ) THEN 'filed_as_junk'
    WHEN EXISTS (
      SELECT 1 FROM delivery_events de
      WHERE de.case_id = dc.id AND de.event_type = 'review_notice_delivered'
    ) THEN 'ask_user'
    ELSE 'deliver'
  END AS outcome,
  (
    SELECT CASE
             WHEN l.label = 'legitimate' THEN 'legitimate'
             WHEN l.label IN ('spam', 'dangerous', 'suspect') THEN 'spam'
             ELSE 'ambiguous'
           END
    FROM labels l
    WHERE l.message_id = m.id AND l.is_ground_truth AND l.active
    ORDER BY l.created_at DESC LIMIT 1
  ) AS truth
FROM messages m
JOIN delivery_cases dc ON dc.message_id = m.id
WHERE m.captured_at > now() - ($1 * interval '1 day')
  AND m.delivery_status <> 'consumed'
  -- Un dossier abandonne faute de reponse n'est ni une reussite ni un echec :
  -- le compter comme sollicitation ferait du silence de l'utilisateur une
  -- performance de la chaine, dans un sens ou dans l'autre.
  AND dc.state <> 'ignored'
"""


async def collect(
    pool: asyncpg.Pool[Any], *, days: int = DEFAULT_WINDOW_DAYS
) -> dict[str, Any]:
    """Le rapport complet : conditions de validité d'abord, taux ensuite."""
    lignes = [dict(row) for row in await pool.fetch(_ROWS_SQL, days)]
    taux = trec_rates(lignes)
    return {
        "window_days": days,
        # En tête, et jamais en note de bas de page : un taux dont on ignore
        # la couverture se lit comme s'il était mesuré.
        "coverage": labelling_coverage(lignes),
        "matrix": confusion_matrix(lignes),
        "hold_precision": hold_precision(lignes),
        "generalized_risk": generalized_risk(lignes),
        "trec_rates": taux,
        "lam_optimistic": lam_percent(
            taux["hm_optimistic"], taux["sm_optimistic"]
        ),
        "lam_pessimistic": lam_percent(
            taux["hm_pessimistic"], taux["sm_pessimistic"]
        ),
        "utility": utility_score(lignes),
    }


async def publish(
    pool: asyncpg.Pool[Any], *, days: int = DEFAULT_WINDOW_DAYS
) -> dict[str, Any]:
    """Pose le rapport à côté de l'état opérationnel, sans jamais l'altérer."""
    rapport = await collect(pool, days=days)
    await pool.execute(
        """
        INSERT INTO operational_status (component,status,details,observed_at)
        VALUES ($1,'ok',$2::jsonb,now())
        ON CONFLICT (component) DO UPDATE SET
          status='ok', details=EXCLUDED.details, observed_at=now()
        """,
        COMPONENT,
        json.dumps(rapport, ensure_ascii=False, default=str),
    )
    return rapport
