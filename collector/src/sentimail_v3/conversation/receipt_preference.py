"""Le réglage de l'accusé de réception, lu et appliqué sans modèle.

« Désactive l'accusé de réception » est un réglage, pas une directive de
livraison : il n'a rien à faire deviner à un modèle, et un réglage mal deviné
serait pire qu'un réglage ignoré. La phrase se reconnaît par sa forme, le
changement d'état s'applique directement, et il est toujours confirmé - c'est
la bascule qui est confirmée, pas la directive.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

import asyncpg

PREFERENCE_NAME = "directive_receipt_enabled"

# « accusé(s) de réception » en toutes lettres : « active » ou « arrête » seuls
# basculeraient sur des phrases qui parlent d'autre chose.
_OBJET = r"(?:d['e]\s*)?accuses?\s+de\s+reception"
_DESACTIVER = re.compile(
    r"\b(?:desactive[rz]?|coupe[rz]?|arrete[rz]?|stoppe[rz]?|supprime[rz]?|"
    r"(?:ne\s+veux|veux)\s+plus)\b.{0,40}?" + _OBJET,
)
_ACTIVER = re.compile(
    r"\b(?:(?:re)?active[rz]?|remets?|retablis?)\b.{0,40}?" + _OBJET,
)


# Les phrases canoniques qui basculent le réglage vers l'état inverse de
# `currently_enabled`. Toute surface qui propose la bascule d'un clic doit
# pré-remplir sa réponse avec l'une de ces deux phrases exactes : c'est ce qui
# garantit que cliquer envoie exactement ce qu'écrire la phrase à la main
# aurait envoyé, sans jamais passer par le regex ci-dessus pour le vérifier.
_LIBELLE_DESACTIVER = "désactive l'accusé de réception"
_LIBELLE_ACTIVER = "active l'accusé de réception"


def receipt_toggle_label(currently_enabled: bool) -> str:
    """Le libellé de l'action qui bascule l'état inverse de currently_enabled."""
    return _LIBELLE_DESACTIVER if currently_enabled else _LIBELLE_ACTIVER


def receipt_toggle_sentence(currently_enabled: bool) -> str:
    """La phrase à pré-remplir, reconnue par parse_receipt_toggle sans modèle."""
    libelle = receipt_toggle_label(currently_enabled)
    return libelle[0].upper() + libelle[1:] + "."


def _normalized(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", str(value or "").casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def parse_receipt_toggle(text: str) -> bool | None:
    """True pour activer, False pour désactiver, None si rien n'est demandé."""
    normalized = _normalized(text)
    if _DESACTIVER.search(normalized):
        return False
    if _ACTIVER.search(normalized):
        return True
    return None


async def get_receipt_enabled(pool: asyncpg.Pool[Any], participant: str) -> bool:
    """L'état du réglage ; activé par défaut, comme avant son existence."""
    value = await pool.fetchval(
        """
        SELECT (value)::text::boolean FROM participant_preferences
        WHERE participant_email=lower($1) AND name=$2
        """,
        participant,
        PREFERENCE_NAME,
    )
    return True if value is None else bool(value)


async def set_receipt_enabled(
    pool: asyncpg.Pool[Any], participant: str, enabled: bool
) -> None:
    await pool.execute(
        """
        INSERT INTO participant_preferences (participant_email, name, value)
        VALUES (lower($1), $2, $3::jsonb)
        ON CONFLICT (participant_email, name)
        DO UPDATE SET value=$3::jsonb, updated_at=now()
        """,
        participant,
        PREFERENCE_NAME,
        json.dumps(bool(enabled)),
    )
