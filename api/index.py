"""Vercel serverless entrypoint for Xer FastAPI app."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mangum import Mangum
from server import app

handler = Mangum(app, lifespan="off")
