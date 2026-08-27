"""L'état de livraison d'un message, et les seuls chemins qui y mènent.

Dix-neuf endroits écrivaient cet état, dans sept fichiers : le juge, la
conversation, le gardien de revue, la fin de vie des retenues, la capture, la
livraison. Chacun connaissait sa transition, aucun ne connaissait l'ensemble.
Les deux pannes du 12 août viennent de là : un dossier resté « en analyse »
parce que le chemin qui devait le conclure passait ailleurs, et un rejeu qui
oubliait de refaire l'observation.

Les transitions sont donc écrites ici, une fois. Chacune indique d'où elle
accepte de partir : un état terminal ne se rouvre pas, et une transition
impossible ne passe pas en silence — elle retourne False, et l'appelant décide.
"""

from __future__ import annotations

from typing import Any, Protocol

CAPTURED = "captured"
ANALYZING = "analyzing"
HELD = "held"
RELEASE_PENDING = "release_pending"
DEFERRED = "deferred"
DELIVERED = "delivered"
CONSUMED = "consumed"
UNDELIVERABLE = "undeliverable"

# Un message livré ou consommé ne revient pas en arrière : la boîte du
# destinataire ne se reprend pas, et une réponse SMTP n'est pas un dossier.
# Un message sans destinataire non plus : le relais final a refusé l'adresse
# de façon définitive, aucune tentative ultérieure ne la fera exister.
TERMINAL = frozenset({DELIVERED, CONSUMED, UNDELIVERABLE})

ORIGINS: dict[str, tuple[str, ...]] = {
    ANALYZING: (CAPTURED, ANALYZING),
    HELD: (CAPTURED, ANALYZING, HELD),
    RELEASE_PENDING: (CAPTURED, ANALYZING, HELD, DEFERRED),
    DEFERRED: (CAPTURED, ANALYZING, RELEASE_PENDING, DEFERRED),
    DELIVERED: (CAPTURED, ANALYZING, HELD, RELEASE_PENDING, DEFERRED),
    CONSUMED: (CAPTURED, ANALYZING),
    UNDELIVERABLE: (CAPTURED, ANALYZING, HELD, RELEASE_PENDING, DEFERRED),
}


class Executor(Protocol):
    """Un pool ou une connexion : la transition s'inscrit dans la transaction."""

    async def execute(self, query: str, *args: Any) -> str: ...


def _moved(result: str) -> bool:
    return result.rsplit(" ", 1)[-1] != "0"


async def move(
    executor: Executor,
    message_id: str,
    target: str,
    *,
    error: str | None = None,
) -> bool:
    """Fait passer un message dans un état, si le chemin est permis.

    Retourne False quand rien n'a bougé : soit l'état actuel n'autorise pas
    cette transition, soit le message y était déjà. Dans les deux cas
    l'appelant doit le savoir, jamais le supposer.
    """
    origins = ORIGINS.get(target)
    if origins is None:
        raise ValueError(f"état de livraison inconnu : {target}")
    result = await executor.execute(
        """
        UPDATE messages
        SET delivery_status=$2,
            delivered_at=CASE WHEN $2 IN ('delivered','consumed')
                              THEN now() ELSE delivered_at END,
            delivery_attempts=CASE WHEN $2='release_pending'
                                   THEN delivery_attempts + 1
                                   ELSE delivery_attempts END,
            last_delivery_error=$4
        WHERE id=$1::uuid AND delivery_status = ANY($3::text[])
        """,
        message_id,
        target,
        list(origins),
        error,
    )
    return _moved(result)
