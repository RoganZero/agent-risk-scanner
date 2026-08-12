from __future__ import annotations

import os
from pathlib import Path

from .models import Finding, ScanResult, SkippedFile
from .rules import REGEX_RULES, contextual_findings, redact_secret_snippet

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)
TEXT_SUFFIXES = frozenset(
    {
        ".bash",
        ".cjs",
        ".conf",
        ".env",
        ".ini",
        ".js",
        ".json",
        ".jsx",
        ".md",
        ".mjs",
        ".ps1",
        ".py",
        ".sh",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
        ".zsh",
    }
)
MAX_FILE_SIZE = 1_000_000


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return

    for current_root, directory_names, file_names in os.walk(root):
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in DEFAULT_EXCLUDED_DIRS
        )
        for name in sorted(file_names):
            path = Path(current_root, name)
            if (
                path.suffix.lower() in TEXT_SUFFIXES
                or name.lower() in {"dockerfile", "makefile", ".env"}
            ):
                yield path


def _display_path(file_path: Path, root: Path) -> str:
    if root.is_file():
        return root.name
    return file_path.relative_to(root).as_posix()


def scan_path(
    target: str | Path, *, exclude_paths: set[str | Path] | None = None
) -> list[Finding]:
    """Scan a file or directory and return deterministic, deduplicated findings."""

    return scan_project(target, exclude_paths=exclude_paths).findings


def scan_project(
    target: str | Path, *, exclude_paths: set[str | Path] | None = None
) -> ScanResult:
    """Scan a file or directory and return findings plus scan coverage metadata."""

    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"scan target does not exist: {target}")
    excluded = {
        Path(path).expanduser().resolve() for path in (exclude_paths or set())
    }

    findings: list[Finding] = []
    skipped_files: list[SkippedFile] = []
    scanned_files = 0
    for path in _iter_files(root):
        relative_path = _display_path(path, root)
        if path.is_symlink():
            skipped_files.append(SkippedFile(relative_path, "symbolic link skipped"))
            continue
        resolved_path = path.resolve()
        if resolved_path in excluded:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                skipped_files.append(SkippedFile(relative_path, "file exceeds size limit"))
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            skipped_files.append(
                SkippedFile(relative_path, f"read failed: {exc.__class__.__name__}")
            )
            continue

        scanned_files += 1
        lines = content.splitlines()
        for line_number, line in enumerate(lines, 1):
            for rule in REGEX_RULES:
                if rule.applies_to(path) and rule.pattern.search(line):
                    findings.append(
                        Finding(
                            severity=rule.severity,
                            rule_id=rule.rule_id,
                            file_path=relative_path,
                            line_number=line_number,
                            snippet=redact_secret_snippet(line),
                            explanation=rule.explanation,
                            remediation=rule.remediation,
                        )
                    )
        findings.extend(contextual_findings(path, relative_path, lines))

    unique = {
        (finding.rule_id, finding.file_path, finding.line_number): finding
        for finding in findings
    }
    sorted_findings = sorted(
        unique.values(),
        key=lambda finding: (
            -int(finding.severity),
            finding.file_path,
            finding.line_number,
            finding.rule_id,
        ),
    )
    return ScanResult(
        findings=sorted_findings,
        scanned_files=scanned_files,
        skipped_files=sorted(
            skipped_files,
            key=lambda skipped_file: (skipped_file.file_path, skipped_file.reason),
        ),
    )
