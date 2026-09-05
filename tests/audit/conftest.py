"""Shared fixtures and helpers for the audit regression suite."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from analytics.code_auditor.models import CodeUnit
from analytics.code_auditor.rules import run_rule_engine

FIXTURES = Path(__file__).parent / "fixtures"

CASE_HEADER = re.compile(
    r"^[\'/\s]*@case\s+id=(?P<id>[A-Za-z0-9_]+)[^\n]*\n"
    r"(?:[\'/\s]*@expect\s+(?P<expect>[^\n]+)\n)?"
    r"(?:[\'/\s]*@forbid\s+(?P<forbid>[^\n]+)\n)?"
    r"(?:[\'/\s]*@lang\s+(?P<lang>[^\n]+)\n)?",
    re.M,
)


@dataclass(frozen=True)
class FixtureCase:
    case_id: str
    body: str
    language: str
    expect: frozenset[str]
    forbid: frozenset[str]
    source_file: str


def _parse_tag_list(raw: str | None) -> frozenset[str]:
    if not raw:
        return frozenset()
    parts = re.split(r"[\s,|]+", raw.strip())
    return frozenset(p for p in parts if p and p.upper() != "NONE")


def parse_annotated_fixture(path: Path, *, default_lang: str) -> list[FixtureCase]:
    """Parse @case / @expect / @forbid annotated sample files into CodeUnit cases."""
    text = path.read_text(encoding="utf-8")
    matches = list(CASE_HEADER.finditer(text))
    cases: list[FixtureCase] = []
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        # Drop trailing section dividers
        body = re.sub(r"(?m)^[\'/\s]*=+\s*$", "", body).strip()
        if body.startswith("// --- begin ---"):
            body = body.split("// --- begin ---", 1)[-1]
        if "// --- end ---" in body:
            body = body.split("// --- end ---", 1)[0]
        body = body.strip() + "\n"
        lang = (match.group("lang") or default_lang).strip().lower()
        cases.append(
            FixtureCase(
                case_id=match.group("id"),
                body=body,
                language=lang,
                expect=_parse_tag_list(match.group("expect")),
                forbid=_parse_tag_list(match.group("forbid")),
                source_file=path.name,
            )
        )
    return cases


def case_to_unit(case: FixtureCase) -> CodeUnit:
    return CodeUnit(
        source_file=case.source_file,
        element_name=case.case_id,
        element_type="agent" if case.language == "lotusscript" else "scriptlibrary",
        language=case.language,
        event=None,
        body=case.body,
        start_line=1,
        keywords_matched=["Document", "View", "session"],
    )


def rule_ids(unit: CodeUnit) -> set[str]:
    return {f.rule_id for f in run_rule_engine([unit])}


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def lotusscript_cases(fixtures_dir: Path) -> list[FixtureCase]:
    return parse_annotated_fixture(
        fixtures_dir / "lotusscript_samples.lss", default_lang="lotusscript"
    )


@pytest.fixture(scope="session")
def java_cases(fixtures_dir: Path) -> list[FixtureCase]:
    return parse_annotated_fixture(
        fixtures_dir / "java_ssjs_samples.java", default_lang="java"
    )


@pytest.fixture(scope="session")
def mock_xboss_graph(fixtures_dir: Path) -> dict:
    return json.loads((fixtures_dir / "mock_xboss_graph.json").read_text(encoding="utf-8"))


@pytest.fixture
def ls_cases_by_id(lotusscript_cases: list[FixtureCase]) -> dict[str, FixtureCase]:
    return {c.case_id: c for c in lotusscript_cases}


@pytest.fixture
def java_cases_by_id(java_cases: list[FixtureCase]) -> dict[str, FixtureCase]:
    return {c.case_id: c for c in java_cases}
