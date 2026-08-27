"""Le code à usage unique qui accompagne une confirmation de directive.

Une phrase de confirmation fixe est connue de tout le monde : elle prouve
seulement qu'un message dit « CONFIRME MAIA », jamais qu'il vient de la boîte
challengée. Un expéditeur usurpé n'a alors qu'à répondre la même phrase au bon
moment pour valider sa propre directive.

Le code corrige exactement cela. Il est tiré au hasard à chaque challenge,
n'existe que dans le courrier envoyé à la vraie boîte, n'est conservé que haché,
vaut cinq minutes et ne sert qu'une fois. Qui ne lit pas ce courrier ne peut
pas confirmer.

L'alphabet écarte les caractères qui se confondent à la lecture (I, L, O, U,
0, 1) : ce code se recopie à la main, dans un client mail, souvent sur un
téléphone.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

TTL_MINUTES = 5
LENGTH = 6
_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
# La phrase reste obligatoire : le code seul serait confirmé par un simple
# rebond automatique qui recopie le corps du message.
_CONFIRM_WITH_CODE = re.compile(
    r"confirme\s+(?:maia|kitt)\s*[:\-]?\s*([A-Za-z0-9][A-Za-z0-9\s-]{4,14})",
    re.IGNORECASE,
)


def new_code() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(LENGTH))


def normalized(code: str) -> str:
    """Un code lu par un humain : espaces, tirets et casse ne comptent pas."""
    return re.sub(r"[\s-]+", "", code).upper()


def code_hash(code: str) -> str:
    return hashlib.sha256(normalized(code).encode()).hexdigest()


def extract_code(text: str) -> str | None:
    match = _CONFIRM_WITH_CODE.search(text or "")
    if match is None:
        return None
    candidate = normalized(match.group(1))[:LENGTH]
    return candidate if len(candidate) == LENGTH else None


def confirms(text: str, expected_hash: str | None) -> bool:
    """Vrai seulement si la réponse porte le code émis pour ce challenge.

    Sans hash attendu, rien ne confirme : une action antérieure à cette
    protection, ou dont le code n'a pas été enregistré, ne peut pas être
    validée par la seule phrase.
    """
    if not expected_hash:
        return False
    code = extract_code(text)
    if code is None:
        return False
    return hmac.compare_digest(code_hash(code), expected_hash)
