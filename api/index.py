"""Vercel serverless entrypoint — loads FastAPI app from ../api.py without package name clash."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_spec = importlib.util.spec_from_file_location("xer_fastapi", _ROOT / "api.py")
_module = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_module)

app = _module.app

from mangum import Mangum  # noqa: E402

handler = Mangum(app, lifespan="off")
