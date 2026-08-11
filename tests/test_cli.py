import json
from pathlib import Path

from agent_risk_scanner.cli import main


def test_cli_writes_json_report(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.py").write_text("eval(user_input)\n", encoding="utf-8")
    output = tmp_path / "report.json"

    result = main([str(project), "--format", "json", "--output", str(output)])

    assert result == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["findings"][0]["rule_id"] == "EXEC_PYTHON_DYNAMIC"

