"""HTTP Basic Auth gate for the Xer app."""

from __future__ import annotations

import base64
import os

from fastapi.testclient import TestClient


def _auth_header(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_open_when_password_unset(monkeypatch):
    monkeypatch.delenv("XER_APP_PASSWORD", raising=False)
    monkeypatch.delenv("XER_APP_USERNAME", raising=False)
    # Re-import after env change is unnecessary — middleware reads env per request.
    from server import app

    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200


def test_requires_auth_when_password_set(monkeypatch):
    monkeypatch.setenv("XER_APP_PASSWORD", "s3cret-gate")
    monkeypatch.setenv("XER_APP_USERNAME", "xer")
    from server import app

    client = TestClient(app)
    denied = client.get("/api/graphs")
    assert denied.status_code == 401
    assert "WWW-Authenticate" in denied.headers

    # Health stays open for uptime probes
    health = client.get("/api/health")
    assert health.status_code == 200

    ok = client.get("/api/graphs", headers=_auth_header("xer", "s3cret-gate"))
    # 200 list or 503 if DB missing — either means auth passed
    assert ok.status_code in {200, 503}


def test_wrong_password_rejected(monkeypatch):
    monkeypatch.setenv("XER_APP_PASSWORD", "s3cret-gate")
    monkeypatch.setenv("XER_APP_USERNAME", "xer")
    from server import app

    client = TestClient(app)
    bad = client.get("/api/graphs", headers=_auth_header("xer", "nope"))
    assert bad.status_code == 401
