"""La preuve matérielle de danger : ce que le Code interdit de livrer en clair.

Un indice défavorable rattaché à un article actif qui porte
`delivery_barrier=material_danger`. La liste des articles barrières est celle
du Code, lue en base à chaque appel : elle n'est pas recopiée ici, pour qu'une
évolution du Code s'applique aussi à cette garde. Seule la requête est
dupliquée.

La même requête vit, mot pour mot, dans conversation/assistant.py
(`_has_material_danger`). Les deux copies restent justes tant qu'aucune n'est
éditée seule ; qui touchera ce fichier-là l'importera d'ici.
"""

from __future__ import annotations

from typing import Any, Protocol


class Executor(Protocol):
    async def fetchval(self, query: str, *args: Any) -> Any: ...


async def has_material_danger(executor: Executor, message_id: str) -> bool:
    """Le Code retient-il, sur ce message, une preuve matérielle de danger ?"""
    return bool(
        await executor.fetchval(
            """
            SELECT EXISTS (
                SELECT 1
                FROM clues c
                JOIN investigations i ON i.id=c.investigation_id
                JOIN code_articles a ON a.article_code=c.article_code
                WHERE i.message_id=$1::uuid
                  AND c.direction='adverse'
                  AND a.enabled=true
                  AND a.parameters->>'delivery_barrier'='material_danger'
            )
            """,
            message_id,
        )
    )
