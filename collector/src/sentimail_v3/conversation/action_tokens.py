from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

REFERENCE_TOKEN_RE = re.compile(r"<s3\.([A-Za-z0-9_-]{20,})@[^>]+>")
ACTION_MARKER_RE = re.compile(r"\bS3-ACTION:([A-Za-z0-9_-]{20,})\b")


def action_token(secret: str, action_id: str, nonce: str | None = None) -> str:
    """Jeton d'une action, lié au secret d'instance et à un aléa par émission.

    Sans aléa, le jeton se déduit de l'identifiant de l'action : rejouer une
    émission produirait le même secret partagé, et la compromission du secret
    d'instance rendrait dérivable tout jeton passé ou futur. Le nonce n'est
    jamais conservé en clair, seul le SHA-256 du jeton l'est.
    """
    material = f"{action_id}:{nonce}" if nonce else action_id
    digest = hmac.new(secret.encode(), material.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

