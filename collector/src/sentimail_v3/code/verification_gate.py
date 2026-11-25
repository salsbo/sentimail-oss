"""La fausse page « vérifiez que vous êtes humain », et comment la distinguer d'un vrai mur.

Un vrai contrôle anti-robot (Cloudflare, DataDome, un captcha d'hébergeur) est
un REFUS : il répond au scanner par un statut d'erreur - 403 le plus souvent -
et ne sert la page qu'après. C'est ce que ``sender_site.is_interstitial`` lit
comme neutre : le pare-feu parle, pas l'expéditeur.

Le faux sas fait l'inverse. C'est une page ordinaire, servie en 200, posée sur
un espace de stockage ou un hébergement jetable, qui ne contient QUE le décor
d'une vérification (« Slide to verify ») et aucun lien : le bouton déclenche en
script la suite, qui est la collecte. Il sert à deux choses, toutes deux
trompeuses : faire croire à un site protégé, et arrêter les scanners avant la
page d'hameçonnage.

Mesuré sur 60 jours (16 septembre 2026) : les pages courtes au vocabulaire de
vérification servies en 200, sans lien visible, hors du domaine de
l'expéditeur, n'ont touché aucun message légitime (storage.googleapis.com,
cloudclusters.net, netlify.app). Les vrais murs légitimes répondaient 403 ; la
salle d'attente de billetterie servie en 200 portait ses liens de langue.
"""

from __future__ import annotations

import re
import unicodedata

# Ce qu'une page dit quand elle prétend vérifier un humain. Pas les refus
# génériques (« access denied », « enable javascript ») : ils ne jouent aucun
# rôle et ne font croire à rien.
_VOCABULAIRE = (
    "verify you are human",
    "verify you are a human",
    "verifying you are human",
    "verifying that you are not a robot",
    "prove you are human",
    "are you a robot",
    "not a robot",
    "pas un robot",
    "human verification",
    "bot verification",
    "verification required",
    "slide to verify",
    "captcha",
    "verification de securite",
)
# Au-delà, la page dit autre chose qu'une vérification.
LONGUEUR_MAX = 200
# Une vérification s'annonce d'emblée.
DEBUT = 150


def _normalize(value: str) -> str:
    stripped = unicodedata.normalize("NFKD", value.casefold())
    ascii_only = "".join(c for c in stripped if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", ascii_only)).strip()


def is_fake_verification_gate(
    *,
    final_status: object,
    body_excerpt: object,
    visible_link_count: object,
    final_apex: object,
    sender_apex: object,
) -> bool:
    """La page vue par le bac à sable est-elle un sas de vérification factice ?

    Quatre conditions, toutes nécessaires : servie en 200 (un vrai mur refuse),
    courte et ouverte sur le vocabulaire de vérification, sans aucun lien
    visible (il n'y a rien d'autre que le décor), hors du domaine de
    l'expéditeur (un site qui protège sa propre page n'emprunte rien).
    """
    if not isinstance(final_status, int) or isinstance(final_status, bool):
        return False
    if final_status != 200:
        return False
    if not isinstance(visible_link_count, int) or visible_link_count != 0:
        return False
    apex = str(final_apex or "").casefold()
    if not apex or apex == str(sender_apex or "").casefold():
        return False
    texte = _normalize(str(body_excerpt or ""))
    if not texte or len(texte) > LONGUEUR_MAX:
        return False
    ouverture = texte[:DEBUT]
    return any(motif in ouverture for motif in _VOCABULAIRE)
