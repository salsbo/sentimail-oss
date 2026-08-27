"""Les écarts humain/modèle, enregistrés pour être instruits.

Un désaccord n'était qu'une ligne de rapport recalculée sur sept jours
glissants : rien ne distinguait un écart déjà analysé d'un écart jamais vu, et
le même constat renaissait à chaque glissement de fenêtre. Chaque désaccord
devient ici un enregistrement durable, ouvert tant qu'un exploitant ne l'a pas
acquitté depuis la console. L'acquittement classe le dossier ; il ne retire
jamais l'écart des mesures.

Ce module n'écrit que la table ``discrepancies``. Il ne juge rien : la
comparaison reprend exactement les quatre sens de ``disagreement_directions``,
et un couple qui n'entre dans aucun sens n'est pas un écart.
"""

from __future__ import annotations

from typing import Any

import asyncpg

# Les deux sens qui sont de vraies erreurs : le système a tranché à l'envers.
REAL_ERROR_DIRECTIONS = ("laisse_passer", "erreur_de_qualification")

# Le même classement que disagreement_directions, dit en SQL. L'ordre des
# WHEN reproduit l'ordre des elif : « suspect » est à la fois une issue
# indécise (côté modèle) et un jugement adverse (côté humain).
_DIRECTION_CASE = """
    CASE
      WHEN modele IN ('suspect','undetermined')
           AND humain IN ('spam','dangerous','suspect')
        THEN 'demande_au_lieu_de_classer'
      WHEN modele IN ('suspect','undetermined') AND humain = 'legitimate'
        THEN 'demande_au_lieu_de_livrer'
      WHEN humain = 'legitimate' AND modele IN ('spam','dangerous')
        THEN 'erreur_de_qualification'
      WHEN humain IN ('spam','dangerous','suspect') AND modele = 'legitimate'
        THEN 'laisse_passer'
    END
"""


async def record(pool: asyncpg.Pool[Any], prompt_version: str) -> int:
    """Enregistre les écarts nouveaux ; les écarts connus restent tels quels.

    La date d'un écart est celle du jugement humain, pas celle du cycle qui le
    constate. Seule la version de prompt déployée décrit le système actuel :
    un désaccord avec un moteur retiré n'appelle aucun réglage.
    """
    result = await pool.execute(
        f"""
        INSERT INTO discrepancies
          (message_id, label_id, human_label, model_classification,
           model_confidence, model_rationale, direction, prompt_version,
           created_at)
        SELECT message_id, label_id, humain, modele, confiance, raisonnement,
               {_DIRECTION_CASE}, prompt_version, label_created_at
        FROM (
            SELECT DISTINCT ON (l.id)
                   l.message_id, l.id AS label_id, l.label AS humain,
                   vr.response->'verdict'->>'classification' AS modele,
                   (vr.response->'verdict'->>'confidence')::float AS confiance,
                   vr.response->'verdict'->>'rationale' AS raisonnement,
                   vr.prompt_version, l.created_at AS label_created_at
            FROM labels l
            JOIN investigations i ON i.message_id = l.message_id
            JOIN verdict_runs vr ON vr.investigation_id = i.id
                                AND vr.status = 'complete'
            WHERE l.active
              AND l.label <> vr.response->'verdict'->>'classification'
              AND vr.prompt_version = $1
            ORDER BY l.id, vr.created_at DESC
        ) ecart
        WHERE ({_DIRECTION_CASE}) IS NOT NULL
        ON CONFLICT (label_id) DO NOTHING
        """,
        prompt_version,
    )
    try:
        return int(result.rsplit(" ", 1)[-1])
    except (ValueError, AttributeError):
        return 0


async def open_counts(pool: asyncpg.Pool[Any]) -> dict[str, int]:
    """Les écarts encore ouverts, par sens. Un dict complet, zéros compris."""
    rows = await pool.fetch(
        """
        SELECT direction, count(*) AS count
        FROM discrepancies
        WHERE acknowledged_at IS NULL
        GROUP BY direction
        """
    )
    counts = {
        "demande_au_lieu_de_classer": 0,
        "demande_au_lieu_de_livrer": 0,
        "erreur_de_qualification": 0,
        "laisse_passer": 0,
    }
    for row in rows:
        direction = str(row["direction"])
        if direction in counts:
            counts[direction] = int(row["count"])
    return counts
