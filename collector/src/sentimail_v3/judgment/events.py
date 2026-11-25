"""Journal des étapes du jugement, sans nouvelle autorité de décision."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from sentimail_v3.code.reference import nommer_dossier
from sentimail_v3.judgment.dossier_view import _json

logger = logging.getLogger("sentimail-v3-verdict")
def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    level = logging.ERROR if event.endswith(".error") else logging.INFO
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": logging.getLevelName(level).lower(),
        "event": event,
        **fields,
    }
    logger.log(level, _json(payload))
