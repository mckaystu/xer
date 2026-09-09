"""Tests for XER_AI_CONFIDENCE_MIN gate."""

from __future__ import annotations

from analytics.code_auditor.llm_engine import ai_confidence_min, _parse_confidence


def test_ai_confidence_min_default(monkeypatch):
    monkeypatch.delenv("XER_AI_CONFIDENCE_MIN", raising=False)
    assert ai_confidence_min() == 75


def test_ai_confidence_min_from_env(monkeypatch):
    monkeypatch.setenv("XER_AI_CONFIDENCE_MIN", "80")
    assert ai_confidence_min() == 80
    monkeypatch.setenv("XER_AI_CONFIDENCE_MIN", "0")
    assert ai_confidence_min() == 0
    monkeypatch.setenv("XER_AI_CONFIDENCE_MIN", "150")
    assert ai_confidence_min() == 100
    monkeypatch.setenv("XER_AI_CONFIDENCE_MIN", "nope")
    assert ai_confidence_min() == 75


def test_parse_confidence():
    assert _parse_confidence(82) == 82
    assert _parse_confidence("90") == 90
    assert _parse_confidence(None, default=70) == 70
    assert _parse_confidence("bad", default=70) == 70
    assert _parse_confidence(-5) == 0
    assert _parse_confidence(200) == 100
