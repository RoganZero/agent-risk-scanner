from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Severity values sort from highest to lowest risk."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Severity
    rule_id: str
    file_path: str
    line_number: int
    snippet: str
    explanation: str
    remediation: str

    def to_dict(self) -> dict[str, str | int]:
        result = asdict(self)
        result["severity"] = self.severity.name
        return result


@dataclass(frozen=True, slots=True)
class SkippedFile:
    file_path: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: list[Finding]
    scanned_files: int
    skipped_files: list[SkippedFile] = field(default_factory=list)

    @property
    def scan_complete(self) -> bool:
        return not self.skipped_files
