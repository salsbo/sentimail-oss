"""Import des modules purs du file-sandbox sans démarrer son serveur HTTP."""

from __future__ import annotations

import sys
from pathlib import Path

SANDBOX_ROOT = Path(__file__).resolve().parents[1]
if str(SANDBOX_ROOT) not in sys.path:
    sys.path.insert(0, str(SANDBOX_ROOT))
