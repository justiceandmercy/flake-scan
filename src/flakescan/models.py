"""Core data models and rule catalog for flake-scan."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


class Severity(str, Enum):
    """Severity levels used by findings and configuration."""

    CRITICAL = "critical"
    ERROR = "error"
    HIGH = "high"
    WARNING = "warning"
    MEDIUM = "medium"
    INFO = "info"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Higher numbers represent more severe findings."""
        return {
            "critical": 4,
            "error": 3,
            "high": 3,
            "warning": 2,
            "medium": 2,
            "info": 1,
            "low": 1,
        }[self.value]

    @classmethod
    def normalize(cls, value: Any) -> "Severity":
        """Normalize a string or enum value to a ``Severity``."""
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            aliases = {
                "err": "error",
                "warn": "warning",
                "information": "info",
            }
            normalized = aliases.get(value.strip().lower(), value.strip().lower())
            try:
                return cls(normalized)
            except ValueError as exc:
                raise ValueError(f"Invalid severity value: {value!r}") from exc
        raise ValueError(f"Invalid severity value: {value!r}")


@dataclass(frozen=True)
class Rule:
    """Definition of a single flake-scan rule."""

    id: str
    title: str
    description: str
    default_severity: Severity = Severity.WARNING
    enabled: bool = True
    tags: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()
    fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "default_severity": self.default_severity.value,
            "enabled": self.enabled,
            "tags": list(self.tags),
            "examples": list(self.examples),
            "fix": self.fix,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Rule":
        return cls(
            id=str(data["id"]),
            title=str(data.get("title", data["id"])),
            description=str(data.get("description", "")),
            default_severity=Severity.normalize(data.get("default_severity", "warning")),
            enabled=bool(data.get("enabled", True)),
            tags=tuple(data.get("tags", ())),
            examples=tuple(data.get("examples", ())),
            fix=str(data.get("fix", "")),
        )


@dataclass
class Finding:
    """A single scanner finding."""

    rule_id: str
    message: str
    path: str
    line: int = 1
    column: int = 0
    end_line: int | None = None
    severity: Severity = Severity.WARNING
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            object.__setattr__(self, "severity", Severity.normalize(self.severity))
        if isinstance(self.path, Path):
            object.__setattr__(self, "path", str(self.path))
        if self.line < 1:
            object.__setattr__(self, "line", 1)
        if self.column < 0:
            object.__setattr__(self, "column", 0)
        if not self.fingerprint:
            digest = hashlib.sha256(
                f"{self.rule_id}:{self.path}:{self.line}:{self.message}".encode("utf-8")
            ).hexdigest()[:16]
            object.__setattr__(self, "fingerprint", digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
            "file": self.path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Finding":
        return cls(
            rule_id=str(data.get("rule_id", data.get("rule", "unknown"))),
            message=str(data.get("message", "")),
            path=str(data.get("path", data.get("file", ""))),
            line=int(data.get("line", 1)),
            column=int(data.get("column", 0)),
            end_line=data.get("end_line"),
            severity=Severity.normalize(data.get("severity", "warning")),
            fingerprint=str(data.get("fingerprint", "")),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class ScanResult:
    """Aggregate result of scanning a project."""

    root: Path | str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return {
            "root": str(self.root),
            "files_scanned": self.files_scanned,
            "duration_seconds": self.duration_seconds,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": {
                "total": len(self.findings),
                "by_severity": counts,
            },
            "config": self.config,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScanResult":
        return cls(
            root=data.get("root", "."),
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            files_scanned=int(data.get("files_scanned", 0)),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            config=dict(data.get("config", {})),
        )

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts


BUILTIN_RULES: list[Rule] = [
    Rule(
        "unseeded-random",
        "Unseeded randomness",
        "Random calls are not seeded, making test outcomes non-deterministic.",
        Severity.WARNING,
        tags=("determinism",),
        examples=("random.random()", "random.randint(0, 10)"),
        fix="Seed the RNG explicitly or inject a deterministic random source.",
    ),
    Rule(
        "time-based-assertion",
        "Time-based assertion",
        "Assertions depend on wall-clock or monotonic time.",
        Severity.WARNING,
        tags=("determinism",),
        examples=("assert time.time() > start",),
        fix="Replace time reads with an injected clock or fixed timestamp.",
    ),
    Rule(
        "real-sleep",
        "Real sleep",
        "Tests call real sleep functions instead of awaiting deterministic conditions.",
        Severity.ERROR,
        tags=("timing", "race-condition"),
        examples=("time.sleep(1)",),
        fix="Use polling with a timeout or an event-based wait.",
    ),
    Rule(
        "retry-loop",
        "Retry loop",
        "Loops retry operations and can hide race conditions.",
        Severity.WARNING,
        tags=("timing", "race-condition"),
        examples=("while not ready: time.sleep(0.1)",),
        fix="Wait for a specific condition with a bounded timeout.",
    ),
    Rule(
        "live-network",
        "Live network call",
        "Tests make real network requests.",
        Severity.ERROR,
        tags=("isolation",),
        examples=("requests.get(url)",),
        fix="Mock the HTTP client or use a local test server.",
    ),
    Rule(
        "live-filesystem",
        "Live filesystem mutation",
        "Tests mutate the real filesystem.",
        Severity.WARNING,
        tags=("isolation",),
        examples=("open(path, 'w')",),
        fix="Use a temporary directory or in-memory filesystem.",
    ),
    Rule(
        "live-database",
        "Live database call",
        "Tests connect to a real database.",
        Severity.ERROR,
        tags=("isolation",),
        examples=("sqlite3.connect(path)",),
        fix="Use a transactional test database or repository mock.",
    ),
    Rule(
        "shared-mutable-state",
        "Shared mutable state",
        "Module or class state can leak between tests.",
        Severity.WARNING,
        tags=("state", "isolation"),
        examples=("CACHE = {}",),
        fix="Reset state in setup/teardown or use fixtures.",
    ),
    Rule(
        "missing-teardown",
        "Missing teardown",
        "Mutable test resources are not cleaned up.",
        Severity.INFO,
        tags=("state",),
        examples=("resource = create_resource()",),
        fix="Add teardown or use context managers/fixtures.",
    ),
    Rule(
        "order-dependent-test",
        "Order-dependent test",
        "Test relies on execution order or global fixtures.",
        Severity.WARNING,
        tags=("ordering",),
        examples=("@pytest.mark.order(1)",),
        fix="Remove ordering markers and make each test independent.",
    ),
    Rule(
        "global-fixture",
        "Global fixture",
        "A global fixture leaks state across tests.",
        Severity.INFO,
        tags=("fixtures", "state"),
        examples=("@pytest.fixture(scope='session')",),
        fix="Narrow fixture scope and reset mutable state.",
    ),
]


def get_rule(rule_id: str) -> Rule | None:
    """Return a built-in rule by id."""
    for rule in BUILTIN_RULES:
        if rule.id == rule_id:
            return rule
    return None


def all_rules() -> list[Rule]:
    """Return all built-in rules."""
    return list(BUILTIN_RULES)


def rules_by_tag(tag: str) -> list[Rule]:
    """Return rules containing a tag."""
    return [rule for rule in BUILTIN_RULES if tag in rule.tags]
