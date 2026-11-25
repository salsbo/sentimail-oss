"""Représentations PostgreSQL des textes observés, sans changer l'original."""

from __future__ import annotations

import json
from typing import Any


def pg_text(value: Any) -> Any:
    """PostgreSQL refuse U+0000 : la projection garde sa place avec U+FFFD."""
    return value.replace("\x00", "\ufffd") if isinstance(value, str) else value


def pg_jsonsafe(value: Any) -> Any:
    """Traite aussi les clés et valeurs imbriquées ; les octets restent intacts."""
    if isinstance(value, str):
        return pg_text(value)
    if isinstance(value, dict):
        return {pg_text(key): pg_jsonsafe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [pg_jsonsafe(item) for item in value]
    if isinstance(value, tuple):
        return tuple(pg_jsonsafe(item) for item in value)
    return value


def pg_json(value: object) -> str:
    """Sérialise les seules projections JSON, jamais les données brutes du mail."""
    return json.dumps(pg_jsonsafe(value), ensure_ascii=False, separators=(",", ":"),
                      default=lambda item: pg_text(str(item)))
