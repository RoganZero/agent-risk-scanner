from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Pattern

from .models import Finding, Severity


@dataclass(frozen=True, slots=True)
class RegexRule:
    rule_id: str
    severity: Severity
    pattern: Pattern[str]
    explanation: str
    remediation: str
    file_suffixes: tuple[str, ...] = ()

    def applies_to(self, path: Path) -> bool:
        return not self.file_suffixes or path.suffix.lower() in self.file_suffixes


def _rule(
    rule_id: str,
    severity: Severity,
    pattern: str,
    explanation: str,
    remediation: str,
    *,
    suffixes: tuple[str, ...] = (),
) -> RegexRule:
    return RegexRule(
        rule_id=rule_id,
        severity=severity,
        pattern=re.compile(pattern, re.IGNORECASE),
        explanation=explanation,
        remediation=remediation,
        file_suffixes=suffixes,
    )


REGEX_RULES: tuple[RegexRule, ...] = (
    # Secrets
    _rule(
        "SECRET_API_KEY",
        Severity.HIGH,
        r"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY)\b\s*[:=]\s*['\"]?(?!\s*(?:os\.|process\.env|\$\{|<|your[_-]))[^\s'\"]{8,}",
        "A likely API credential is embedded in source or configuration and may be exposed through version control.",
        "Revoke exposed credentials, remove them from history, and load secrets from an approved secret store or environment variable.",
    ),
    _rule(
        "SECRET_GITHUB_TOKEN",
        Severity.HIGH,
        r"\b(?:GITHUB_TOKEN\s*[:=]\s*['\"]?(?!\s*(?:os\.|process\.env|\$\{|<|your[_-]))[^\s'\"]{8,}|gh[pousr]_[A-Za-z0-9_]{20,})",
        "A likely GitHub token is hard-coded and could grant repository or organization access.",
        "Revoke the token, purge it from history, and inject a least-privilege token at runtime.",
    ),
    _rule(
        "SECRET_WEBHOOK_URL",
        Severity.HIGH,
        r"https?://[^\s'\"]*(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|webhook)[^\s'\"]*",
        "A webhook URL may contain a bearer-like secret that permits unauthorized message delivery or automation calls.",
        "Rotate the webhook and store its URL as a secret rather than committing it.",
    ),
    _rule(
        "SECRET_BEARER_TOKEN",
        Severity.HIGH,
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}",
        "A bearer token appears to be embedded in the project and can be replayed by anyone who obtains it.",
        "Revoke the token and supply short-lived credentials through a secure runtime channel.",
    ),
    # Dangerous execution
    _rule(
        "EXEC_PYTHON_DYNAMIC",
        Severity.HIGH,
        r"(?<![\w.])(?:eval|exec)\s*\(",
        "Dynamic Python execution can turn untrusted text into arbitrary code execution.",
        "Replace dynamic execution with a parser, explicit dispatch table, or a constrained data format.",
        suffixes=(".py",),
    ),
    _rule(
        "EXEC_OS_SYSTEM",
        Severity.HIGH,
        r"\bos\.system\s*\(",
        "os.system invokes a shell, where untrusted input can cause command injection.",
        "Use a fixed executable with subprocess and an argument list; validate every variable argument.",
        suffixes=(".py",),
    ),
    _rule(
        "EXEC_SUBPROCESS",
        Severity.MEDIUM,
        r"\bsubprocess\.(?:run|Popen|call|check_call|check_output|getoutput|getstatusoutput)\s*\(",
        "Launching a subprocess expands the program's authority and becomes dangerous when arguments are attacker-controlled.",
        "Use a fixed executable, pass an argument list, keep shell=False, validate inputs, and run with least privilege.",
        suffixes=(".py",),
    ),
    _rule(
        "EXEC_NODE_CHILD_PROCESS",
        Severity.HIGH,
        r"(?:child_process|childProcess)\.(?:exec|execSync|spawn|spawnSync)\s*\(",
        "Node child_process execution can allow arbitrary command execution when data is not constrained.",
        "Use an allowlisted executable and validated argument array; avoid shell execution.",
        suffixes=(".js", ".cjs", ".mjs", ".ts", ".tsx"),
    ),
    _rule(
        "SHELL_RECURSIVE_DELETE",
        Severity.HIGH,
        r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+(?:/|~|\$HOME|\$\{HOME\}|[^\s]+)",
        "A forced recursive delete may destroy a large directory tree and can be catastrophic with a malformed path.",
        "Resolve and verify the target path, restrict it to an application-owned directory, and prefer a recoverable delete.",
        suffixes=(".sh", ".bash", ".zsh", ".ps1", ".md", ".yaml", ".yml"),
    ),
    _rule(
        "SHELL_REMOTE_PIPE",
        Severity.HIGH,
        r"\b(?:curl\b[^|\n]*\|\s*(?:ba)?sh\b|wget\b[^|\n]*\|\s*(?:ba)?sh\b)",
        "Piping a network response directly to a shell executes unverified remote code.",
        "Download to a file, verify a pinned checksum or signature, inspect it, and then execute explicitly.",
        suffixes=(".sh", ".bash", ".zsh", ".ps1", ".md", ".yaml", ".yml"),
    ),
    # File system
    _rule(
        "FS_RECURSIVE_DELETE",
        Severity.HIGH,
        r"\b(?:shutil\.rmtree|fs\.rmSync|fs\.rm)\s*\(",
        "Recursive deletion can remove unintended files when its target is broad or attacker-controlled.",
        "Canonicalize the target and enforce that it is inside an application-owned root before deletion.",
        suffixes=(".py", ".js", ".cjs", ".mjs", ".ts", ".tsx"),
    ),
    _rule(
        "FS_DELETE_USER_HOME",
        Severity.HIGH,
        r"(?:shutil\.rmtree\s*\(\s*(?:Path\.home\(\)|os\.path\.expanduser\(['\"]~['\"]\))|rm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+['\"]?(?:~|\$HOME|\$\{HOME\})['\"]?)",
        "The deletion target resolves to a user's home directory and may destroy personal data.",
        "Never delete a home directory; constrain deletion to a verified application-specific subdirectory.",
    ),
    _rule(
        "FS_SENSITIVE_READ",
        Severity.HIGH,
        r"(?:open|read_text|readFile(?:Sync)?)\s*\([^\n]*(?:\.ssh|\.aws|\.config|\.env)|(?:\.ssh|\.aws|\.config|\.env)[^\n]*(?:read_text|readFile(?:Sync)?|open)\s*\(",
        "The code reads a location that commonly contains credentials or sensitive user configuration.",
        "Request explicit permission, limit reads to a documented file, and avoid collecting unrelated credentials.",
    ),
    _rule(
        "FS_UNTRUSTED_WRITE_PATH",
        Severity.MEDIUM,
        r"(?:open\s*\(\s*(?:user_?(?:input|path)|target_path|path)\s*,\s*['\"][wax+]|(?:user_?(?:input|path)|target_path|path)\.(?:write_text|write_bytes)\s*\(|(?:writeFile|writeFileSync)\s*\(\s*(?:user_?(?:input|path)|targetPath|path)\b)",
        "A caller-controlled path appears to be used for writing and may escape the intended project directory.",
        "Resolve the path, reject traversal, and require it to remain beneath a dedicated writable root.",
    ),
    # Network
    _rule(
        "NET_USER_CONTROLLED_URL",
        Severity.HIGH,
        r"(?:requests\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete)|fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*(?:input\s*\(|user_?(?:input|url)|target_url|url)\b",
        "User-controlled data appears to select the request destination, enabling SSRF or access to internal services.",
        "Parse the URL and enforce an HTTPS host allowlist; reject private, loopback, link-local, and metadata addresses.",
    ),
    _rule(
        "NET_EXTERNAL_REQUEST_NO_ALLOWLIST",
        Severity.MEDIUM,
        r"(?:requests\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete)|fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['\"]https?://(?!localhost\b|127\.0\.0\.1\b)",
        "The code sends an external request, but no destination allowlist is evident at this call site.",
        "Centralize outbound requests and enforce a documented allowlist, timeouts, response limits, and TLS verification.",
    ),
    _rule(
        "NET_POSSIBLE_EXFILTRATION",
        Severity.HIGH,
        r"(?:requests|httpx)\.(?:post|put|patch)\s*\([^\n]*(?:data|json|files)\s*=|\bcurl\b[^\n]*(?:--data|-d\s|--upload-file|-T\s)",
        "The code transmits local data to a remote endpoint and could expose prompts, files, secrets, or user content.",
        "Minimize transmitted fields, redact secrets, require an approved destination, and obtain explicit user authorization.",
    ),
    # Direct untrusted input into privileged sinks
    _rule(
        "AGENT_INPUT_TO_COMMAND",
        Severity.HIGH,
        r"(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|child_process\.(?:exec|spawn))\s*\([^\n]*(?:input\s*\(|user_?(?:input|command)|command|query)\b",
        "User-controlled input appears to flow directly into a command execution sink.",
        "Map user intent to a small allowlist of operations and pass validated arguments without a shell.",
    ),
    _rule(
        "AGENT_INPUT_TO_PATH",
        Severity.MEDIUM,
        r"(?:open|Path|readFile|writeFile|unlink|rmtree)\s*\(\s*(?:input\s*\(|user_?(?:input|path)|target_path)\b",
        "User-controlled input appears to be used directly as a filesystem path.",
        "Resolve and validate the path against explicit read/write roots and reject traversal or absolute paths.",
    ),
)


TOOL_MARKERS = re.compile(
    r"(?:@(?:\w+\.)?(?:tool|command)\b|\b(?:Tool|StructuredTool)\s*\(|\b(?:mcp|server)\.tool\s*\()",
    re.IGNORECASE,
)
SHELL_SINK = re.compile(
    r"(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|child_process\.(?:exec|spawn))\s*\(",
    re.IGNORECASE,
)
FILE_SINK = re.compile(
    r"(?:\bopen\s*\(|Path\s*\(|readFile|writeFile|shutil\.rmtree)", re.IGNORECASE
)
BOUNDARY_TERMS = re.compile(
    r"\b(?:security|safety|permission|allowlist|denylist|sandbox|boundary|untrusted|validation)\b|安全|权限|白名单|边界|不可信|校验",
    re.IGNORECASE,
)
ENV_CREDENTIAL = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)\s*=\s*(?!\s*$|\s*['\"]?\$\{|\s*['\"]?<)[^#\s]{6,}",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT = re.compile(
    r"(?P<prefix>\b[A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|WEBHOOK_URL)\s*[:=]\s*)(?P<quote>['\"]?)(?P<value>[^\s'\"]{6,})(?P=quote)",
    re.IGNORECASE,
)
BEARER_VALUE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{12,}")
GITHUB_TOKEN_VALUE = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", re.IGNORECASE)
WEBHOOK_VALUE = re.compile(
    r"https?://[^\s'\"]*(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|webhook)[^\s'\"]*",
    re.IGNORECASE,
)
CONTEXTUAL_RULE_SEVERITIES: dict[str, Severity] = {
    "SECRET_ENV_CREDENTIAL": Severity.HIGH,
    "AGENT_TOOL_SHELL_ACCESS": Severity.HIGH,
    "AGENT_TOOL_ARBITRARY_FILE_ACCESS": Severity.HIGH,
    "AGENT_MISSING_SECURITY_BOUNDARY": Severity.LOW,
}
RULE_SEVERITIES: dict[str, Severity] = {
    **{rule.rule_id: rule.severity for rule in REGEX_RULES},
    **CONTEXTUAL_RULE_SEVERITIES,
}
ALL_RULE_IDS: tuple[str, ...] = tuple(RULE_SEVERITIES)


def redact_secret_snippet(line: str) -> str:
    """Preserve useful location context without copying credentials into reports."""

    value = line.strip()
    value = SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group('prefix')}{match.group('quote')}<redacted>{match.group('quote')}",
        value,
    )
    value = BEARER_VALUE.sub(r"\1<redacted>", value)
    value = GITHUB_TOKEN_VALUE.sub("<redacted-github-token>", value)
    value = WEBHOOK_VALUE.sub("<redacted-webhook-url>", value)
    return value


def contextual_findings(path: Path, relative_path: str, lines: list[str]) -> list[Finding]:
    """Run rules that need file-level context instead of a single-line match."""

    findings: list[Finding] = []
    content = "\n".join(lines)

    if path.name.lower() == ".env" or path.suffix.lower() == ".env":
        for line_number, line in enumerate(lines, 1):
            if ENV_CREDENTIAL.search(line):
                findings.append(
                    Finding(
                        Severity.HIGH,
                        "SECRET_ENV_CREDENTIAL",
                        relative_path,
                        line_number,
                        redact_secret_snippet(line),
                        "A .env file contains a credential-like value that may be committed or copied with the project.",
                        "Keep .env files out of version control, provide a redacted .env.example, and load real values from a secret store.",
                    )
                )

    if TOOL_MARKERS.search(content):
        for line_number, line in enumerate(lines, 1):
            if SHELL_SINK.search(line):
                findings.append(
                    Finding(
                        Severity.HIGH,
                        "AGENT_TOOL_SHELL_ACCESS",
                        relative_path,
                        line_number,
                        line.strip(),
                        "A declared agent/MCP tool can launch shell commands, giving model-controlled actions broad host authority.",
                        "Expose narrow typed operations, enforce command and argument allowlists, and isolate execution in a sandbox.",
                    )
                )
            if FILE_SINK.search(line) and re.search(
                r"(?:user_?(?:input|path)|target_path|path|filename)", line, re.IGNORECASE
            ):
                findings.append(
                    Finding(
                        Severity.HIGH,
                        "AGENT_TOOL_ARBITRARY_FILE_ACCESS",
                        relative_path,
                        line_number,
                        line.strip(),
                        "A declared tool appears to use a caller-controlled filesystem path and may read or modify arbitrary files.",
                        "Give the tool a fixed workspace root, canonicalize paths, and enforce operation-specific read/write permissions.",
                    )
                )

    name = path.name.lower()
    is_prompt_or_skill = name == "skill.md" or (
        "prompt" in name and path.suffix.lower() in {".md", ".txt", ".yaml", ".yml"}
    )
    if is_prompt_or_skill and content.strip() and not BOUNDARY_TERMS.search(content):
        first_content_line = next(
            (index for index, value in enumerate(lines, 1) if value.strip()), 1
        )
        findings.append(
            Finding(
                Severity.LOW,
                "AGENT_MISSING_SECURITY_BOUNDARY",
                relative_path,
                first_content_line,
                lines[first_content_line - 1].strip(),
                "This prompt or skill defines behavior without an explicit security boundary for permissions and untrusted input.",
                "Document allowed operations, forbidden targets, permission requirements, input validation, and safe failure behavior.",
            )
        )

    return findings
