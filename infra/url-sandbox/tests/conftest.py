from __future__ import annotations

import sys
from pathlib import Path

SANDBOX_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SANDBOX_ROOT))
