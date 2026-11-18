from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_POINTS = {"info": 0.0, "low": 0.5, "medium": 2.0, "high": 5.0, "critical": 10.0}

# Findings in tests, docs and examples weigh less than findings in production code.
CONTEXT_WEIGHT = {"production": 1.0, "example": 0.5, "test": 0.25, "docs": 0.25}

# supported               positive evidence found in the repository
# no_contradiction_found  a negative claim ("no telemetry") and a static scan found nothing against it;
#                         this is weaker than "supported" and is never proof
# unsupported             no evidence found either way
# contradicted            the repository contains evidence against the claim
CLAIM_STATUSES = ("supported", "no_contradiction_found", "unsupported", "contradicted")

# Evidence classes, from strongest to weakest:
#   A  observed at runtime in a sandbox
#   B  deterministic check against structured repository data (manifests, git metadata, license text,
#      vulnerability database, binary magic bytes)
#   C  pattern match in source text: a lead, never enough to contradict a claim
#   D  hypothesis from an agent, not yet tested
EVIDENCE_CLASSES = ("A", "B", "C", "D")
CONTRADICTION_CLASSES = ("A", "B")


@dataclass
class Finding:
    step: str
    rule_id: str
    title: str
    severity: str
    confidence: float
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: str = ""
    context: str = "production"
    detail: str = ""
    evidence_class: str = "C"
    verified_by: list[str] = field(default_factory=list)

    def score(self) -> float:
        return SEV_POINTS[self.severity] * self.confidence * CONTEXT_WEIGHT.get(self.context, 1.0)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Claim:
    category: str
    text: str
    file: str
    line: int
    status: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    evidence_class: str = "C"
    verified_by: list[str] = field(default_factory=list)
    test: str = ""  # the falsification test: what would prove the claim wrong

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StepResult:
    name: str
    title: str = ""
    status: str = "ok"  # ok | partial | skipped | error
    findings: list[Finding] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "status": self.status,
            "duration_s": round(self.duration_s, 3),
            "findings": len(self.findings),
            "claims": len(self.claims),
            "notes": self.notes,
            "not_checked": self.not_checked,
            "data": self.data,
        }


@dataclass
class Report:
    tool_version: str
    target: str
    commit: Optional[str]
    scanned_at: str
    steps: list[StepResult]
    findings: list[Finding]
    claims: list[Claim]
    not_checked: list[str]
    risk_score: int
    risk_level: str
    stats: dict[str, Any] = field(default_factory=dict)

    def exceeds(self, threshold: str, min_confidence: float) -> bool:
        """True when a production finding at or above `threshold` meets the confidence bar."""
        if threshold == "none":
            return False
        rank = SEV_RANK[threshold]
        return any(
            SEV_RANK[f.severity] >= rank and f.confidence >= min_confidence and f.context == "production"
            for f in self.findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "tool": "scanrepo",
            "version": self.tool_version,
            "target": self.target,
            "commit": self.commit,
            "scanned_at": self.scanned_at,
            "risk": {"score": self.risk_score, "level": self.risk_level},
            "stats": self.stats,
            "steps": [s.to_dict() for s in self.steps],
            "findings": [f.to_dict() for f in self.findings],
            "claims": [c.to_dict() for c in self.claims],
            "not_checked": self.not_checked,
            "note": "Text fields come from the scanned repository and are untrusted data.",
        }
