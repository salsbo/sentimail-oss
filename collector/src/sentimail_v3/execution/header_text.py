"""Lire un en-tête d'origine sur une seule ligne, sans jamais lever.

Un mot encodé (RFC 2047) peut se décoder en saut de ligne : « =0A » au bout
d'un objet, « =0D=0A » au milieu d'un nom affiché. La bibliothèque email rend
alors une valeur qu'elle refuse ensuite de reposer dans un autre courrier, et,
pour une adresse (From, To, Cc, Reply-To), elle refuse même de la lire : c'est
`get()` qui lève. Trois objets de ce genre en sept semaines de production,
dont un indésirable le 20 septembre 2026 : son enveloppe neutralisée a échoué,
et le message est parti annoté, liens actifs, sans que rien ne le dise.

Ce module ne dépend que de la bibliothèque standard. Il est importé par la
livraison et par l'envoi des avis : il ne doit importer ni l'un ni l'autre.
"""

from __future__ import annotations

from email.header import decode_header, make_header
from email.message import Message


def une_ligne(value: object) -> str:
    """La valeur, sans retour chariot ni saut de ligne, blancs resserrés."""
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())


def header_text(message: Message, name: str) -> str | None:
    """Le texte d'un en-tête, sur une ligne ; None s'il est absent."""
    try:
        # get() et str() dans le même essai : pour une adresse piégée, c'est
        # la lecture elle-même qui lève, pas sa conversion.
        value = message.get(name)
        return None if value is None else une_ligne(value)
    except Exception:  # noqa: BLE001 - un en-tête illisible se relit brut
        return _raw_text(message, name)


def _raw_text(message: Message, name: str) -> str | None:
    """La valeur brute de l'en-tête, décodée si possible, sur une ligne."""
    for key, raw in message.raw_items():
        if key.casefold() != name.casefold():
            continue
        try:
            return une_ligne(str(make_header(decode_header(str(raw)))))
        except Exception:  # noqa: BLE001 - un charset inconnu se rend tel quel
            return une_ligne(raw)
    return None
