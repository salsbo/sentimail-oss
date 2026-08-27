"""Le dernier contrôle avant qu'un courrier quitte SentiMail.

Aucun email ne doit partir sans expéditeur. La règle paraît évidente, et elle a
pourtant été enfreinte deux fois dans la même journée, par deux chemins
différents : les lettres de contrôle qualité passaient des chaînes vides à la
file d'envoi, et l'enveloppe des indésirables ne posait tout simplement pas
d'en-tête « From ». Dans les deux cas, le destinataire recevait un message venu
de personne, dont le bouton « Répondre » ne menait nulle part.

Corriger chaque appelant l'un après l'autre laisse le suivant libre de
recommencer. Le contrôle vit donc au seul endroit que tout courrier sortant
franchit : la remise au relais.

Il refuse, il ne répare pas. Poser un expéditeur par défaut ferait partir le
courrier en masquant le défaut, et personne ne saurait jamais qu'un chemin
d'envoi est incomplet.
"""

from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import TypeVar

Envelope = TypeVar("Envelope", bytes, EmailMessage)


def _from_header(message: Envelope) -> str:
    if isinstance(message, EmailMessage):
        return str(message.get("from") or "")
    parsed: EmailMessage = BytesParser(policy=policy.default).parsebytes(message)
    return str(parsed.get("from") or "")


def require_sender(message: Envelope, recipient: object) -> Envelope:
    """Rend le message tel quel, ou refuse s'il partirait de personne."""
    destinataires = recipient if isinstance(recipient, (list, tuple)) else [recipient]
    if not any(str(value or "").strip() for value in destinataires):
        raise ValueError("courrier sortant sans destinataire")
    if not _from_header(message).strip():
        raise ValueError("courrier sortant sans expéditeur : refusé avant le relais")
    return message
