# Rule Reference

This document describes the rules implemented in v0.1.0. All rules are heuristic static checks. A match identifies code that needs review; it does not prove reachability, exploitability, or malicious intent.

## Severity model

- **HIGH:** likely credential exposure, arbitrary execution, destructive/sensitive access, SSRF, exfiltration, or broad tool authority.
- **MEDIUM:** a dangerous capability whose impact depends on surrounding validation, destination policy, or runtime configuration.
- **LOW:** a defense-in-depth or documentation gap without a direct exploit demonstrated by the match.

## Secrets

| rule_id | Severity | Detection logic | Suggested remediation |
| --- | --- | --- | --- |
| `SECRET_API_KEY` | HIGH | Matches hard-coded assignments to `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`, excluding common environment/placeholder forms. | Revoke exposed values, remove them from history, and inject secrets from an approved runtime store. |
| `SECRET_GITHUB_TOKEN` | HIGH | Matches hard-coded `GITHUB_TOKEN` assignments and GitHub token prefixes such as `ghp_` with token-like length. | Revoke and purge the token; replace it with a least-privilege runtime credential. |
| `SECRET_WEBHOOK_URL` | HIGH | Matches Slack, Discord, or URL text containing a webhook marker. | Rotate the webhook and store the URL as a secret. |
| `SECRET_BEARER_TOKEN` | HIGH | Matches a literal `Bearer` value with at least 12 token-like characters. | Revoke the value and use short-lived credentials supplied at runtime. |
| `SECRET_ENV_CREDENTIAL` | HIGH | In `.env` files, matches variable names ending in key/token/secret/password/credential forms with a non-placeholder value. | Exclude real `.env` files from version control and use a redacted `.env.example` plus a secret store. |

Secret findings pass through report redaction. Detection remains heuristic and does not validate whether a credential is active.

## Code and shell execution

| rule_id | Severity | Detection logic | Suggested remediation |
| --- | --- | --- | --- |
| `EXEC_PYTHON_DYNAMIC` | HIGH | In Python files, matches calls to `eval(...)` or `exec(...)`. | Use a parser, constrained data format, or explicit dispatch table. |
| `EXEC_OS_SYSTEM` | HIGH | In Python files, matches `os.system(...)`. | Use a fixed executable with a subprocess argument list and validated values. |
| `EXEC_SUBPROCESS` | MEDIUM | In Python files, matches common `subprocess` launch helpers including `run`, `Popen`, `call`, and output helpers. | Keep `shell=False`, use fixed executables and argument lists, validate inputs, and run with least privilege. |
| `EXEC_NODE_CHILD_PROCESS` | HIGH | In JavaScript/TypeScript files, matches `child_process`/`childProcess` exec or spawn helpers. | Use an allowlisted executable and validated argument array without a shell. |
| `SHELL_RECURSIVE_DELETE` | HIGH | In shell/config/Markdown-like files, matches forced recursive `rm` forms. | Canonicalize and verify a narrow application-owned target; prefer recoverable deletion. |
| `SHELL_REMOTE_PIPE` | HIGH | In shell/config/Markdown-like files, matches `curl ... \| sh/bash` or `wget ... \| sh/bash`. | Download first, verify a pinned checksum/signature, inspect, then execute explicitly. |

## File system

| rule_id | Severity | Detection logic | Suggested remediation |
| --- | --- | --- | --- |
| `FS_RECURSIVE_DELETE` | HIGH | Matches Python `shutil.rmtree` and selected Node `fs.rm`/`fs.rmSync` calls. | Require the canonical target to remain within a dedicated application-owned root. |
| `FS_DELETE_USER_HOME` | HIGH | Matches selected recursive deletion forms that explicitly target `Path.home()`, expanded `~`, `~`, or `$HOME`. | Never delete a home directory; restrict deletion to a verified application subdirectory. |
| `FS_SENSITIVE_READ` | HIGH | Matches selected read/open APIs on lines mentioning `.ssh`, `.aws`, `.config`, or `.env`. | Require explicit permission and restrict reads to a documented file and purpose. |
| `FS_UNTRUSTED_WRITE_PATH` | MEDIUM | Matches selected write APIs receiving path variables named like `user_path`, `target_path`, or `path`. | Resolve the path, reject traversal/absolute escapes, and enforce a writable root. |

## Network

| rule_id | Severity | Detection logic | Suggested remediation |
| --- | --- | --- | --- |
| `NET_USER_CONTROLLED_URL` | HIGH | Matches selected requests/httpx/fetch/axios calls receiving `input()`, user URL/input, target URL, or URL-shaped variables. | Parse URLs, require HTTPS and an approved host, and reject loopback/private/link-local/metadata addresses. |
| `NET_EXTERNAL_REQUEST_NO_ALLOWLIST` | MEDIUM | Matches selected request APIs called with a literal external HTTP(S) URL, excluding localhost and `127.0.0.1`. | Centralize egress and enforce host allowlists, timeouts, response limits, and TLS verification. |
| `NET_POSSIBLE_EXFILTRATION` | HIGH | Matches selected requests/httpx POST/PUT/PATCH calls with `data`, `json`, or `files`, plus curl upload/data flags. | Minimize and redact payloads, approve destinations, and require user authorization. |

## Agent, MCP, prompt, and Skill boundaries

| rule_id | Severity | Detection logic | Suggested remediation |
| --- | --- | --- | --- |
| `AGENT_TOOL_SHELL_ACCESS` | HIGH | When a file contains a common tool declaration marker, flags selected shell/process sinks elsewhere in that file. | Replace general command tools with narrow typed operations, command allowlists, and sandboxing. |
| `AGENT_TOOL_ARBITRARY_FILE_ACCESS` | HIGH | When a file contains a common tool marker, flags selected file APIs using caller-shaped path or filename variables. | Enforce canonical workspace roots and operation-specific read/write permissions. |
| `AGENT_MISSING_SECURITY_BOUNDARY` | LOW | For `SKILL.md` or prompt-named text/config files, reports no recognized language about security, permissions, allowlists, sandboxing, boundaries, untrusted input, or validation. | Document allowed/forbidden actions, permissions, input validation, and safe failure behavior. |
| `AGENT_INPUT_TO_COMMAND` | HIGH | Matches selected command sinks that directly contain `input()` or variables named like user input/command, command, or query. | Map user intent to an operation allowlist and pass validated arguments without a shell. |
| `AGENT_INPUT_TO_PATH` | MEDIUM | Matches selected file/path sinks directly receiving `input()` or user/target path-shaped variables. | Canonicalize the path, reject traversal and absolute escapes, and enforce read/write roots. |

## Scanner boundaries

- Rules generally operate on one line; the two tool rules and the missing-boundary rule use file-level context.
- The scanner reads configured text suffixes, ignores files over 1 MB, and skips common vendor/generated directories such as `.git`, virtual environments, build output, and `node_modules`.
- It does not perform full taint analysis, dependency vulnerability scanning, Git-history scanning, semantic prompt-injection detection, or runtime permission evaluation.
- Multiple rule IDs may intentionally match one line when it represents separate risks, such as both a general recursive delete and explicit home-directory deletion.

