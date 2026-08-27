"""Poser une cle de fournisseur sur disque, et rien d'autre.

Faire transiter un secret par la messagerie etait la cause de tout : un refus
SMTP renvoyait la cle dans un rapport de non-remise, et l'archive chiffree que
le protocole reclamait etait comptee par la chaine elle-meme comme une charge
adverse forte. La console la pose directement, derriere Tailscale, sans qu'elle
traverse aucune boite aux lettres.

Ce module n'ecrit jamais en base et ne relit jamais ce qu'il a ecrit. La cle
entre par un formulaire, sort sur disque, et disparait de la memoire du
processus. Aucune page de cette console ne sait la relire - c'est verifie par
les tests, parce qu'une capacite de lecture non utilisee finit par l'etre.

L'ecriture est atomique : un fichier temporaire en 0600, puis un remplacement.
Un service qui lirait pendant l'ecriture verrait l'ancienne cle ou la nouvelle,
jamais une cle tronquee.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

# Le nom de fichier suit celui que la base valide (``llm_role_providers.
# secret_filename``) : lettres minuscules, chiffres, tiret bas.
_FILENAME_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")


def write_named_secret(directory: str, filename: str, key: str) -> str:
    """Ecrit la cle sous le nom de fichier donne, et rend ce nom.

    Le nom n'est plus deduit d'un fournisseur connu d'avance : il est fourni
    par l'appelant (typiquement ``presets.secret_filename_for``) et valide ici
    contre le meme alphabet que la contrainte SQL, pour qu'aucune saisie ne
    puisse designer un chemin hors du dossier des secrets.
    """
    if not _FILENAME_PATTERN.match(filename):
        raise ValueError(f"nom de fichier invalide : {filename!r}")
    valeur = str(key or "").strip()
    if not valeur:
        raise ValueError("cle vide")
    # Une cle sur deux lignes serait lue tronquee par le service qui la charge.
    if any(caractere in valeur for caractere in ("\n", "\r")):
        raise ValueError("la cle ne peut pas contenir de saut de ligne")

    cible = Path(directory)
    cible.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(cible, 0o700)
    descripteur, temporaire = tempfile.mkstemp(prefix=".incoming-", dir=cible)
    try:
        os.fchmod(descripteur, 0o600)
        with os.fdopen(descripteur, "w", encoding="utf-8") as flux:
            flux.write(valeur)
            flux.write("\n")
            flux.flush()
            os.fsync(flux.fileno())
        os.replace(temporaire, cible / filename)
    finally:
        if os.path.exists(temporaire):
            os.unlink(temporaire)
    return filename
