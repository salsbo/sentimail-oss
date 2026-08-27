from __future__ import annotations

import re

_QUEUE_ID = re.compile(r"\bqueued as\s+([A-Za-z0-9]+)\b", re.IGNORECASE)


def extract_queue_id(send_result: object) -> str | None:
    match = _QUEUE_ID.search(str(send_result))
    return match.group(1)[:128] if match else None
