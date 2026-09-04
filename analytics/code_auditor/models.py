"""Domino DXL / On-Disk code quality auditor — models and rule IDs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
ConfidenceBand = Literal["high", "medium", "low"]

RULE_CATALOG: dict[str, dict[str, str]] = {
    "DOM-001": {
        "title": "Inline Chained Domino Object Instantiation",
        "category": "C-API Handle Leaks & Object Recycling",
        "default_severity": "CRITICAL",
    },
    "DOM-002": {
        "title": "Un-Recycled Collection Iteration",
        "category": "C-API Handle Leaks & Object Recycling",
        "default_severity": "CRITICAL",
    },
    "DOM-003": {
        "title": "Missing try-finally Recycling Scaffolding",
        "category": "C-API Handle Leaks & Object Recycling",
        "default_severity": "HIGH",
    },
    "DOM-004": {
        "title": "Manual recycle() on OpenNTF Domino API Objects",
        "category": "Framework Conflicts",
        "default_severity": "CRITICAL",
    },
    "DOM-005": {
        "title": "Mixed lotus.domino / ODA Object Passing",
        "category": "Framework Conflicts",
        "default_severity": "HIGH",
    },
    "DOM-006": {
        "title": "Static Domino Handle Field",
        "category": "Static Variables & Lifetime Anti-Patterns",
        "default_severity": "CRITICAL",
    },
    "DOM-007": {
        "title": "Unsafe Scope / Static Cache of Native Handles",
        "category": "Static Variables & Lifetime Anti-Patterns",
        "default_severity": "HIGH",
    },
    "DOM-008": {
        "title": "Expensive Column/Document Fetch Inside Loop",
        "category": "High-Memory & Expensive Data Patterns",
        "default_severity": "MEDIUM",
    },
    "DOM-009": {
        "title": "Inline createDateTime Chaining in Loop/Hot Path",
        "category": "High-Memory & Expensive Data Patterns",
        "default_severity": "MEDIUM",
    },
    "DOM-010": {
        "title": "Missing Try-Finally Recycling Block",
        "category": "C-API Handle Leaks & Object Recycling",
        "default_severity": "HIGH",
    },
    "DOM-011": {
        "title": "Orphaned Child Handle / Early Parent Recycling",
        "category": "C-API Handle Leaks & Object Recycling",
        "default_severity": "CRITICAL",
    },
    "DOM-012": {
        "title": "Conditional or Incomplete Loop Recycling",
        "category": "C-API Handle Leaks & Object Recycling",
        "default_severity": "HIGH",
    },
    "DOM-013": {
        "title": "Unsafe Object Re-assignment",
        "category": "C-API Handle Leaks & Object Recycling",
        "default_severity": "MEDIUM",
    },
}


@dataclass
class CodeUnit:
    """A single extractable code block from DXL or ODP."""

    source_file: str
    element_name: str
    element_type: str
    language: str
    event: str | None
    body: str
    start_line: int = 1
    keywords_matched: list[str] = field(default_factory=list)

    @property
    def line_count(self) -> int:
        return max(1, self.body.count("\n") + 1)


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: int
    source_file: str
    element_name: str
    element_type: str
    language: str
    line: int
    evidence: str
    technical_impact: str
    remediation: str
    action_required: str
    category: str = ""
    engine: str = "rules"  # rules | llm | hybrid
    code_snippet_as_is: str = ""
    code_snippet_to_be: str = ""
    line_number_start: int = 0
    line_number_end: int = 0
    handle_lifecycle_warning: str = ""

    def confidence_band(self) -> ConfidenceBand:
        if self.confidence >= 90:
            return "high"
        if self.confidence >= 70:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        """Full finding payload including deep-dive snippet fields."""
        data = asdict(self)
        data["confidence_band"] = self.confidence_band()
        # API-friendly aliases requested by the deep-dive UI
        data["finding_id"] = self.id
        data["issue"] = self.title
        data["file_path"] = self.source_file
        data["line_number"] = self.line
        data["location"] = f"{self.element_type}:{self.element_name} L{self.line}"
        data["confidence_ratio"] = round(self.confidence / 100.0, 2)
        if not data.get("code_snippet_to_be"):
            data["code_snippet_to_be"] = self.remediation
        if not data.get("code_snippet_as_is"):
            data["code_snippet_as_is"] = self.evidence
        if not data.get("handle_lifecycle_warning"):
            data["handle_lifecycle_warning"] = self.technical_impact
        return data


@dataclass
class AuditReport:
    source: str
    files_scanned: int
    blocks_scanned: int
    blocks_prefiltered: int
    findings: list[Finding] = field(default_factory=list)
    llm_enabled: bool = False
    notes: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def risk_score(self) -> str:
        counts = self.severity_counts()
        if counts["CRITICAL"] >= 3 or (counts["CRITICAL"] >= 1 and counts["HIGH"] >= 3):
            return "CRITICAL"
        if counts["CRITICAL"] >= 1 or counts["HIGH"] >= 3:
            return "HIGH"
        if counts["HIGH"] >= 1 or counts["MEDIUM"] >= 5:
            return "MEDIUM"
        if self.findings:
            return "LOW"
        return "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "files_scanned": self.files_scanned,
            "blocks_scanned": self.blocks_scanned,
            "blocks_prefiltered": self.blocks_prefiltered,
            "llm_enabled": self.llm_enabled,
            "notes": self.notes,
            "severity_counts": self.severity_counts(),
            "handle_exhaustion_risk": self.risk_score(),
            "findings": [f.to_dict() for f in self.findings],
        }
