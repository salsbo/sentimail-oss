"""Chiffrement du message original conservé en base.

La rétention borne la durée pendant laquelle l'original existe ; elle ne dit
rien de sa confidentialité pendant ce temps. Une sauvegarde chiffrée ne protège
pas non plus la base elle-même. L'EML est donc chiffré avant d'être écrit, avec
une clé qui ne vit que dans un secret monté en lecture seule.

Format : `S3E1` + nonce (12 octets) + étiquette GCM (16 octets) + chiffré. Le
préfixe permet de reconnaître un contenu chiffré d'un contenu hérité en clair,
et donc de migrer sans interruption ni perte.
"""

from __future__ import annotations

from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

MAGIC = b"S3E1"
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
ALGORITHM = "aes-256-gcm-v1"


class DecryptionError(RuntimeError):
    """Le contenu existe mais la clé fournie ne permet pas de le lire."""


def load_key(path: str | None) -> bytes | None:
    """Lit la clé de chiffrement, ou None quand aucune n'est configurée."""
    if not path:
        return None
    raw = Path(path).read_bytes().strip()
    key = bytes.fromhex(raw.decode("ascii")) if len(raw) == KEY_BYTES * 2 else raw
    if len(key) != KEY_BYTES:
        raise ValueError("raw EML key must contain exactly 32 bytes")
    return key


def is_encrypted(blob: bytes | None) -> bool:
    return bool(blob) and bytes(blob or b"")[: len(MAGIC)] == MAGIC


def encrypt(data: bytes, key: bytes) -> bytes:
    # Le nonce est fixé explicitement : la longueur par défaut de la
    # bibliothèque n'est pas celle que le format déclare, et le découpage à la
    # lecture doit correspondre à l'octet près.
    nonce = get_random_bytes(NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return MAGIC + nonce + tag + ciphertext


def decrypt(blob: bytes, key: bytes) -> bytes:
    if not is_encrypted(blob):
        return bytes(blob)
    header = len(MAGIC)
    nonce = blob[header : header + NONCE_BYTES]
    tag = blob[header + NONCE_BYTES : header + NONCE_BYTES + TAG_BYTES]
    payload = blob[header + NONCE_BYTES + TAG_BYTES :]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
    try:
        return cipher.decrypt_and_verify(payload, tag)
    except ValueError as exc:  # étiquette invalide : mauvaise clé ou altération
        raise DecryptionError("stored message cannot be decrypted") from exc


def protect(data: bytes, key: bytes | None) -> tuple[bytes, str | None]:
    """Chiffre quand une clé existe, sans jamais bloquer la capture sinon."""
    if key is None:
        return data, None
    return encrypt(data, key), ALGORITHM


def reveal(blob: bytes | None, key: bytes | None) -> bytes | None:
    """Rend l'original lisible, qu'il ait été écrit avant ou après la clé."""
    if blob is None:
        return None
    data = bytes(blob)
    if not is_encrypted(data):
        return data
    if key is None:
        raise DecryptionError("stored message is encrypted but no key is configured")
    return decrypt(data, key)
