# Threat Model

## Purpose and system boundary

`agent-risk-scanner` performs local, read-only static inspection of supported text files and produces a Markdown or JSON report. It does not import, execute, install, or sandbox the target project. The scanner is intended to help reviewers find high-signal locations in AI agent, MCP server, Codex Skill, plugin, and automation repositories.

The target repository and its contents are untrusted input. The scanner assumes that a reviewer controls the scan path and report destination. Findings are evidence of a pattern, not proof of reachability or exploitation.

## Assets and trust boundaries

Important assets include API keys and tokens, user files, SSH/cloud configuration, source code, prompts and conversation data, network credentials, host integrity, and the permissions granted to tools.

The most important trust boundaries are:

1. user, prompt, model, or remote content entering an agent;
2. that content being mapped into a tool argument;
3. a tool crossing into the shell, filesystem, or network;
4. a plugin, Skill, package, installer, or update source introducing executable behavior;
5. scanner findings being written to a report that may be retained or shared.

## Threats and current coverage

### Secret leakage

Secrets may be committed in source or `.env` files, embedded in bearer headers or webhook URLs, read from sensitive user directories, or copied into a report. Current rules recognize selected OpenAI/Anthropic key assignments, GitHub tokens, webhook URLs, bearer tokens, credential-like `.env` entries, and reads mentioning `.ssh`, `.aws`, `.config`, or `.env`. Secret-like snippets are redacted in reports.

Coverage is pattern-based. The scanner does not inspect Git history, entropy, binary files, remote secret stores, logs, or every provider token format.

### Shell execution

Model or user input that reaches `eval`, `exec`, `os.system`, Python subprocess APIs, Node child processes, or shell installer patterns can result in arbitrary execution. Current rules flag those execution primitives, direct input-shaped variables at selected command sinks, forced recursive deletion, and `curl`/`wget` piped to a shell.

The scanner does not perform interprocedural taint tracking, resolve wrappers or aliases, or determine whether a subprocess argument was validated elsewhere.

### File system access

Over-broad tools can read credentials, overwrite files outside a workspace, follow traversal paths, or recursively delete data. Current rules flag selected sensitive reads, recursive deletion primitives, explicit home-directory deletion, caller-controlled paths at selected read/write sinks, and tool files that combine a tool marker with caller-shaped path use.

The scanner does not evaluate symbolic links, runtime path canonicalization, operating-system ACLs, container mounts, or every filesystem API.

### Network exfiltration

An agent may send prompts, files, environment data, or credentials to an attacker-controlled endpoint. User-controlled URLs also create SSRF risk against loopback, private, link-local, or cloud metadata services. Current rules flag selected request APIs receiving URL-shaped user input, literal external request destinations without an allowlist evident at the call site, and selected POST/PUT/PATCH or curl upload patterns.

The scanner does not resolve DNS, evaluate runtime allowlists, inspect TLS behavior, trace payload contents across functions, or prove that a transmission is unauthorized.

### Prompt injection

Untrusted instructions can manipulate an agent into invoking legitimate tools with unsafe arguments or exceeding the user's intent. The current implementation does not semantically detect prompt injection. It provides limited supporting checks: prompt/`SKILL.md` files without recognized security-boundary terms, and direct input-shaped values passed to selected command, path, or URL sinks.

Human review must assess instruction precedence, content provenance, tool-call confirmation, output handling, memory poisoning, indirect prompt injection, and whether untrusted content can modify policy.

### MCP and tool permission abuse

An MCP server or agent tool may expose shell execution or arbitrary file access with authority greater than the task requires. Current contextual checks look for common tool declaration markers in a file and flag selected shell sinks or caller-controlled filesystem operations in that same file.

This is file-level correlation, not a full MCP schema or permission analysis. Reviewers must inspect tool schemas, authentication, capability scoping, per-call authorization, audit logs, workspace roots, network egress, and human approval gates.

### Supply chain risk

Install scripts, dependencies, plugins, Skills, and MCP servers can introduce malicious or compromised code. The current scanner only covers a narrow subset: direct remote-script-to-shell pipelines and dangerous primitives visible in scanned text files.

It does not detect vulnerable dependency versions, dependency confusion, typosquatting, malicious package lifecycle hooks in general, unsigned releases, compromised actions, provenance failures, or changes in remote content. Use lockfiles, pinned and reviewed dependencies, artifact signatures or attestations, dependency scanners, restricted CI permissions, and trusted release processes alongside this tool.

## Scanner-specific risks

- **False positives:** a dangerous primitive may be safely constrained by context the regex cannot see.
- **False negatives:** aliases, wrappers, multiline flows, alternative languages, encoding tricks, or unsupported file types may evade detection.
- **Sensitive reports:** paths and code context can still be sensitive even when credential values are redacted. Store and share reports accordingly.
- **Resource limits:** files larger than 1 MB and typical generated/vendor directories are skipped. This limits resource use but leaves those files outside coverage.
- **Report injection:** Markdown snippets escape backticks, but reports should still be treated as untrusted content when rendered by other systems.

## Expected controls outside the scanner

Use least-privilege credentials, explicit filesystem roots and network allowlists, sandboxed execution, human confirmation for destructive or external actions, dependency and Git-history scanning, code review, runtime logging, incident response, and periodic permission review. A clean scan does not mean a project is secure.

