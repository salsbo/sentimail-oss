"""Bascule des originaux hérités vers le stockage chiffré.

Chaque message est relu, chiffré et réécrit dans une transaction, puis vérifié
en le déchiffrant : un original n'est jamais remplacé par un contenu qu'on ne
saurait pas relire. La commande est interruptible et reprenable, puisqu'elle ne
sélectionne que ce qui reste en clair.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

import asyncpg

from sentimail_v3.config import load_settings
from sentimail_v3.crypto import ALGORITHM, DecryptionError, decrypt, encrypt, load_key


async def pending_count(pool: asyncpg.Pool[Any]) -> int:
    return int(
        await pool.fetchval(
            """
            SELECT count(*) FROM messages
            WHERE raw_eml IS NOT NULL AND raw_eml_encryption IS NULL
            """
        )
        or 0
    )


async def encrypt_batch(
    pool: asyncpg.Pool[Any], key: bytes, batch: int
) -> tuple[int, int]:
    """Chiffre un lot d'originaux ; retourne les compteurs (chiffrés, échecs)."""
    rows = await pool.fetch(
        """
        SELECT id::text AS id, raw_eml FROM messages
        WHERE raw_eml IS NOT NULL AND raw_eml_encryption IS NULL
        ORDER BY captured_at
        LIMIT $1
        """,
        batch,
    )
    done = 0
    failed = 0
    for row in rows:
        original = bytes(row["raw_eml"])
        sealed = encrypt(original, key)
        try:
            if decrypt(sealed, key) != original:
                raise DecryptionError("round trip mismatch")
        except DecryptionError:
            failed += 1
            continue
        await pool.execute(
            """
            UPDATE messages SET raw_eml=$2, raw_eml_encryption=$3
            WHERE id=$1::uuid AND raw_eml_encryption IS NULL
            """,
            row["id"],
            sealed,
            ALGORITHM,
        )
        done += 1
    return done, failed


async def run(batch: int, apply: bool) -> None:
    settings = load_settings()
    key = load_key(settings.raw_eml_key_file)
    if key is None:
        raise SystemExit(
            "RAW_EML_KEY_FILE n'est pas configuré : aucune clé, aucun chiffrement."
        )
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        remaining = await pending_count(pool)
        print(f"{remaining} original/originaux encore en clair.")
        if not apply or not remaining:
            if remaining:
                print("Relance avec --apply pour les chiffrer.")
            return
        total = 0
        while True:
            done, failed = await encrypt_batch(pool, key, batch)
            total += done
            if failed:
                raise SystemExit(
                    f"{failed} original/originaux non vérifiables : bascule interrompue."
                )
            if not done:
                break
            print(f"{total} chiffré(s)…")
        left = await pending_count(pool)
        print(f"Terminé : {total} chiffré(s), {left} restant(s) en clair.")
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.execution.encrypt_at_rest",
        description="Chiffre les originaux herites encore stockes en clair.",
    )
    parser.add_argument("--batch", type=int, default=50)
    parser.add_argument("--apply", action="store_true")
    arguments = parser.parse_args()
    asyncio.run(run(max(1, arguments.batch), arguments.apply))


if __name__ == "__main__":
    main()
