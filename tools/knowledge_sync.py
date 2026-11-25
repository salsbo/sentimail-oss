"""Fige les sources normatives dans le dépôt, une fois pour toutes.

Une connaissance qu'on retélécharge à l'usage n'est plus une référence : elle
change sans qu'on le sache, et une réponse d'hier devient inexplicable. Les
documents sont donc capturés ici, sur le poste, vérifiés par leur empreinte et
versionnés avec le code. La production ne télécharge rien et n'a aucun accès
réseau à accorder pour lire une RFC.

Usage : python tools/knowledge_sync.py [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE = ROOT / "knowledge"
SNAPSHOTS = KNOWLEDGE / "snapshots"
MANIFEST = KNOWLEDGE / "manifest.json"
USER_AGENT = "Mozilla/5.0 (compatible)"

# Uniquement des normes et des spécifications : stables, publiques, citables.
# La veille et les annuaires n'ont pas leur place ici, ils ne se vérifient pas
# de la même manière.
SOURCES: list[dict[str, str]] = [
    {
        "id": "rfc5321",
        "title": "RFC 5321 - Simple Mail Transfer Protocol",
        "url": "https://www.rfc-editor.org/rfc/rfc5321.txt",
        "topic": "smtp",
    },
    {
        "id": "rfc5322",
        "title": "RFC 5322 - Internet Message Format",
        "url": "https://www.rfc-editor.org/rfc/rfc5322.txt",
        "topic": "format",
    },
    {
        "id": "rfc5598",
        "title": "RFC 5598 - Internet Mail Architecture",
        "url": "https://www.rfc-editor.org/rfc/rfc5598.txt",
        "topic": "architecture",
    },
    {
        "id": "rfc6376",
        "title": "RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures",
        "url": "https://www.rfc-editor.org/rfc/rfc6376.txt",
        "topic": "authentification",
    },
    {
        "id": "rfc7208",
        "title": "RFC 7208 - Sender Policy Framework (SPF)",
        "url": "https://www.rfc-editor.org/rfc/rfc7208.txt",
        "topic": "authentification",
    },
    {
        "id": "rfc7489",
        "title": "RFC 7489 - Domain-based Message Authentication (DMARC)",
        "url": "https://www.rfc-editor.org/rfc/rfc7489.txt",
        "topic": "authentification",
    },
    {
        "id": "rfc8601",
        "title": "RFC 8601 - Message Header Field for Indicating Message "
        "Authentication Status",
        "url": "https://www.rfc-editor.org/rfc/rfc8601.txt",
        "topic": "authentification",
    },
    {
        "id": "rfc8617",
        "title": "RFC 8617 - Authenticated Received Chain (ARC)",
        "url": "https://www.rfc-editor.org/rfc/rfc8617.txt",
        "topic": "authentification",
    },
    {
        "id": "rfc8058",
        "title": "RFC 8058 - Signaling One-Click Functionality for List Email "
        "Headers",
        "url": "https://www.rfc-editor.org/rfc/rfc8058.txt",
        "topic": "desabonnement",
    },
    {
        "id": "rfc2142",
        "title": "RFC 2142 - Mailbox Names for Common Services, Roles and "
        "Functions",
        "url": "https://www.rfc-editor.org/rfc/rfc2142.txt",
        "topic": "adressage",
    },
]


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return response.read()


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture les sources normatives.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="recapture même les documents déjà présents",
    )
    arguments = parser.parse_args()
    SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, object]] = []
    for source in SOURCES:
        target = SNAPSHOTS / f"{source['id']}.txt"
        if target.exists() and not arguments.force:
            content = target.read_bytes()
            captured = "inchangé"
        else:
            content = _fetch(source["url"])
            target.write_bytes(content)
            captured = "capturé"
        digest = hashlib.sha256(content).hexdigest()
        entries.append(
            {
                **source,
                "path": str(target.relative_to(KNOWLEDGE)),
                "sha256": digest,
                "bytes": len(content),
                "captured_on": date.today().isoformat(),
            }
        )
        print(f"{source['id']:10s} {captured:9s} {len(content):>8d} o  {digest[:12]}")
    MANIFEST.write_text(
        json.dumps(
            {
                "schema": "sentimail-v3-knowledge-manifest-1",
                "nature": "normative",
                "documents": entries,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"\n{len(entries)} document(s) dans {MANIFEST.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
