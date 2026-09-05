"""AI discrepancy audit integration tests (Pass 1 / Pass 2 / Pass 3).

Uses mocked LLM responses so the suite runs without OPENAI_API_KEY.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from analytics.code_auditor.llm_engine import enrich_with_llm, llm_available
from analytics.code_auditor.models import CodeUnit, Finding, RULE_CATALOG
from analytics.code_auditor.rules import run_rule_engine
from tests.audit.conftest import FixtureCase, case_to_unit


def _finding_stub(**kwargs: Any) -> Finding:
    defaults = dict(
        id="F-001",
        rule_id="LS-DOM-001",
        title="stub",
        severity="HIGH",
        confidence=90,
        source_file="t",
        element_name="X",
        element_type="agent",
        language="lotusscript",
        line=1,
        evidence="Set doc = view.GetFirstDocument()",
        technical_impact="leak",
        remediation="Delete doc",
        action_required="fix",
        category="LotusScript Handle Lifecycle",
    )
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestLlmGating:
    def test_llm_available_false_without_key(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        assert llm_available() is False

    def test_enrich_skips_without_key(self, monkeypatch: pytest.MonkeyPatch, ls_cases_by_id: dict[str, FixtureCase]):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        unit = case_to_unit(ls_cases_by_id["ls_dom001_leak"])
        findings = run_rule_engine([unit])
        out, notes = enrich_with_llm([unit], findings, max_units=5)
        assert out == findings
        assert any("OPENAI_API_KEY" in n for n in notes)

    def test_run_audit_rules_only(self, mock_xboss_graph: dict, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        from analytics.code_auditor import run_audit

        report = run_audit(graph=mock_xboss_graph, use_llm=False)
        assert report.llm_enabled is False
        assert report.findings
        assert any("Rules-only" in n or "OPENAI" in n for n in report.notes)


class TestPass1FalsePositiveFilter:
    def test_marks_false_positive(self, monkeypatch: pytest.MonkeyPatch, ls_cases_by_id: dict[str, FixtureCase]):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
        unit = case_to_unit(ls_cases_by_id["ls_dom001_leak"])
        findings = run_rule_engine([unit])
        assert findings
        first_id = "F-001"

        def fake_chat(system: str, user_payload: dict, *, model: str) -> dict:
            if "FALSE-POSITIVE" in system or "FALSE_POSITIVE" in system:
                fid = user_payload["findings"][0]["finding_id"]
                return {
                    "reviews": [
                        {
                            "finding_id": fid,
                            "verdict": "FALSE_POSITIVE",
                            "confidence": 88,
                            "reasoning": "Custom helper deletes before return.",
                        }
                    ]
                }
            return {"blind_spots": [], "ownership_gaps": [], "severity_adjustments": []}

        with patch("analytics.code_auditor.llm_engine._chat_json", side_effect=fake_chat):
            out, notes = enrich_with_llm([unit], findings, max_units=6)
        fps = [f for f in out if f.is_false_positive]
        assert fps, f"expected FP; notes={notes}"
        assert fps[0].ai_validation_status == "FALSE_POSITIVE"
        assert any("Pass 1" in n for n in notes)

    def test_verifies_real_leak(self, monkeypatch: pytest.MonkeyPatch, ls_cases_by_id: dict[str, FixtureCase]):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
        unit = case_to_unit(ls_cases_by_id["ls_dom001_leak"])
        findings = run_rule_engine([unit])

        def fake_chat(system: str, user_payload: dict, *, model: str) -> dict:
            if "FALSE-POSITIVE" in system or "FALSE_POSITIVE" in system:
                fid = user_payload["findings"][0]["finding_id"]
                return {
                    "reviews": [
                        {
                            "finding_id": fid,
                            "verdict": "VERIFIED",
                            "confidence": 95,
                            "reasoning": "No Delete in loop.",
                        }
                    ]
                }
            return {"blind_spots": [], "ownership_gaps": [], "severity_adjustments": []}

        with patch("analytics.code_auditor.llm_engine._chat_json", side_effect=fake_chat):
            out, _notes = enrich_with_llm([unit], findings, max_units=6)
        verified = [f for f in out if f.ai_validation_status == "VERIFIED"]
        assert verified
        assert not verified[0].is_false_positive


class TestPass2BlindSpotDetector:
    def test_emits_dom_bs_001(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
        # Pass 2 only runs on units with HANDLE_ALLOC_HINT and zero static hits.
        unit = CodeUnit(
            source_file="lib.lss",
            element_name="SubtleLeak",
            element_type="scriptlibrary",
            language="lotusscript",
            event=None,
            body=(
                "Sub Initialize\n"
                "  Dim session As New NotesSession\n"
                "  Dim db As NotesDatabase\n"
                "  Set db = session.CurrentDatabase\n"
                "  Print db.Title\n"
                "End Sub\n"
            ),
            start_line=1,
            keywords_matched=["Database", "session"],
        )
        static = run_rule_engine([unit])
        assert not static, f"fixture must have zero static hits for Pass 2; got { {f.rule_id for f in static} }"

        def fake_chat(system: str, user_payload: dict, *, model: str) -> dict:
            if "BLIND-SPOT" in system or "BLIND_SPOT" in system:
                return {
                    "blind_spots": [
                        {
                            "severity": "HIGH",
                            "confidence": 90,
                            "line_hint": 4,
                            "evidence": "Set db = session.CurrentDatabase",
                            "technical_impact": "NotesDatabase handle not Deleted before exit.",
                            "remediation": "Delete db before End Sub.",
                            "action_required": "Add Delete db in cleanup path.",
                            "reasoning": "Static rules miss session.CurrentDatabase assignment.",
                        }
                    ]
                }
            return {"reviews": [], "ownership_gaps": [], "severity_adjustments": []}

        with patch("analytics.code_auditor.llm_engine._chat_json", side_effect=fake_chat):
            out, notes = enrich_with_llm([unit], [], max_units=8)
        bs = [f for f in out if f.rule_id == "DOM-BS-001" or f.is_blind_spot]
        assert bs, f"expected blind spot; notes={notes}"
        assert bs[0].ai_validation_status == "BLIND_SPOT"
        assert any("Pass 2" in n for n in notes)


class TestPass3CrossModuleOwnership:
    def test_emits_dom_bs_002_and_escalates(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
        callee = CodeUnit(
            source_file="a.lss",
            element_name="FetchDoc",
            element_type="scriptlibrary",
            language="lotusscript",
            event=None,
            body=(
                "Function FetchDoc(unid As String) As NotesDocument\n"
                "  Dim doc As NotesDocument\n"
                "  Set doc = db.GetDocumentByUNID(unid)\n"
                "  Set FetchDoc = doc\n"
                "End Function\n"
            ),
            keywords_matched=["Document"],
        )
        caller = CodeUnit(
            source_file="b.lss",
            element_name="Initialize",
            element_type="agent",
            language="lotusscript",
            event="Initialize",
            body=(
                "Sub Initialize\n"
                "  Dim doc As NotesDocument\n"
                "  Set doc = FetchDoc(unid$)\n"
                "  Print doc.NoteID\n"
                "End Sub\n"
            ),
            keywords_matched=["Document"],
        )
        existing = [
            _finding_stub(
                id="F-001",
                rule_id="LS-DOM-002",
                element_name="Initialize",
                severity="MEDIUM",
            )
        ]

        def fake_chat(system: str, user_payload: dict, *, model: str) -> dict:
            if "CROSS-MODULE" in system or "ownership" in system.lower():
                return {
                    "ownership_gaps": [
                        {
                            "severity": "HIGH",
                            "confidence": 92,
                            "element_name": "FetchDoc",
                            "line_hint": 3,
                            "evidence": "Set FetchDoc = doc",
                            "technical_impact": "Neither caller nor callee Deletes the NotesDocument.",
                            "action_required": "Callee should Delete on error; caller owns success path.",
                            "reasoning": "Returned handle never released.",
                            "execution_context": "background_agent",
                            "escalate": True,
                        }
                    ],
                    "severity_adjustments": [
                        {
                            "finding_id": "F-001",
                            "new_severity": "CRITICAL",
                            "reasoning": "Scheduled agent hot path.",
                        }
                    ],
                }
            return {"reviews": [], "blind_spots": []}

        with patch("analytics.code_auditor.llm_engine._chat_json", side_effect=fake_chat):
            out, notes = enrich_with_llm([callee, caller], existing, max_units=9)

        assert "DOM-BS-002" in RULE_CATALOG
        ownership = [f for f in out if f.rule_id == "DOM-BS-002"]
        assert ownership, f"expected DOM-BS-002; notes={notes}"
        escalated = next(f for f in out if f.id == "F-001" or f.rule_id == "LS-DOM-002")
        # After re-id, find the LS-DOM-002 finding
        ls = [f for f in out if f.rule_id == "LS-DOM-002"]
        assert ls
        assert ls[0].severity == "CRITICAL"
        assert any("Pass 3" in n for n in notes)


class TestAuditReportAiSummary:
    def test_ai_discrepancy_summary_shape(self, monkeypatch: pytest.MonkeyPatch, mock_xboss_graph: dict):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")

        def fake_chat(system: str, user_payload: dict, *, model: str) -> dict:
            return {"reviews": [], "blind_spots": [], "ownership_gaps": [], "severity_adjustments": []}

        from analytics.code_auditor import run_audit

        with patch("analytics.code_auditor.llm_engine._chat_json", side_effect=fake_chat):
            report = run_audit(graph=mock_xboss_graph, use_llm=True, max_llm_units=6)
        payload = report.to_dict()
        assert "ai_discrepancy_summary" in payload
        summary = payload["ai_discrepancy_summary"]
        assert isinstance(summary, dict)
        assert any("Pass 1" in n or "Pass 2" in n or "Pass 3" in n or "AI discrepancy" in n for n in report.notes)
