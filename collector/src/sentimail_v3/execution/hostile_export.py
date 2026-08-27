"""Exporte le registre des sources hostiles en table cidr pour Postfix.

Le MX refuse les connexions des sources du registre - mais il ne doit dépendre
ni de la base ni d'un service au moment d'accepter une connexion : une base
indisponible ferait différer tout le courrier. Le registre est donc exporté en
fichier plat, que les processus smtpd (éphémères) relisent naturellement à
leur démarrage, sans reload.

Les entrées automatiques (verdicts, qualifications) expirent à 30 jours
glissants - une adresse réattribuée ne reste pas bannie à vie, une récidive
prolonge. Les entrées manuelles de l'administrateur restent jusqu'à leur
suppression. L'écriture est atomique, et un contenu inchangé n'est pas
réécrit.

Un rejet à ce niveau est visible dans les journaux du MX (554 explicite,
jamais un drop silencieux) : l'auditabilité reste entière.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any

import asyncpg

REJECT_LINE = "REJECT source refusee par le registre SentiMail"

# Une occurrence isolée peut être un faux positif ou un serveur partagé qui
# émet aussi du légitime : elle s'observe, elle ne se bloque pas. Seule la
# récidive lourde ferme la porte. Une entrée manuelle bloque toujours :
# l'administrateur a déjà tranché. Même seuil côté admin (queries.py).
BLOCK_THRESHOLD = 10


async def export_hostile_cidr(pool: asyncpg.Pool[Any], path: str) -> int:
    """Écrit la table cidr des sources bloquées. Retourne le nombre d'entrées."""
    rows = await pool.fetch(
        f"""
        SELECT ip::text AS ip FROM hostile_smtp_sources
        WHERE last_reason LIKE 'manual%'
           OR (hits >= {BLOCK_THRESHOLD}
               AND last_seen > now() - interval '30 days')
        ORDER BY ip
        """
    )
    lines = []
    for row in rows:
        ip = str(row["ip"])
        if "/" not in ip:
            ip += "/128" if ":" in ip else "/32"
        lines.append(f"{ip}\t{REJECT_LINE}")
    content = "\n".join(lines) + ("\n" if lines else "")

    try:
        with open(path, encoding="utf-8") as existing:
            if existing.read() == content:
                return len(lines)
    except OSError:
        pass
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".hostile.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return len(lines)
