import re
from pathlib import Path

from agent_risk_scanner.rules import ALL_RULE_IDS, RULE_SEVERITIES


def test_rule_reference_matches_implementation():
    project_root = Path(__file__).resolve().parents[1]
    documentation = (project_root / "docs" / "rules.md").read_text(encoding="utf-8")
    documented_rules = dict(
        re.findall(
            r"^\| `([A-Z][A-Z0-9_]+)` \| (HIGH|MEDIUM|LOW) \|",
            documentation,
            re.MULTILINE,
        )
    )

    assert set(documented_rules) == set(ALL_RULE_IDS)
    assert documented_rules == {
        rule_id: severity.name for rule_id, severity in RULE_SEVERITIES.items()
    }
