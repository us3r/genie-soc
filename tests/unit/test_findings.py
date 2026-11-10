import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from genie_soc import RuleError, finding_id, load_rules, to_finding
from genie_soc.findings import FINDING_COLUMNS

ROOT = Path(__file__).resolve().parents[2]
RULES = {rule.id: rule for rule in load_rules(ROOT / "rules")}
NOW = datetime(2026, 11, 10, 21, 0, tzinfo=timezone.utc)
WINDOW = datetime(2026, 11, 10, 19, 45, tzinfo=timezone.utc)

COV_002_ROW = {
    "workspace_id": "1000000000000001",
    "window_start": WINDOW,
    "requests": 12,
    "agent_requests": 0,
    "user_count": 1,
    "users": ["analyst@example.com"],
    "user_id": "analyst@example.com",
    "first_seen": datetime(2026, 11, 10, 19, 57, tzinfo=timezone.utc),
    "last_seen": datetime(2026, 11, 10, 19, 58, tzinfo=timezone.utc),
}


def test_same_key_gives_same_id_across_runs():
    rule = RULES["GENIE-COV-002"]
    later = {**COV_002_ROW, "requests": 40, "last_seen": datetime(2026, 11, 10, 19, 59, tzinfo=timezone.utc)}
    assert finding_id(rule, COV_002_ROW) == finding_id(rule, later)


def test_different_key_or_rule_gives_different_id():
    rule = RULES["GENIE-COV-002"]
    next_window = {**COV_002_ROW, "window_start": datetime(2026, 11, 10, 20, 0, tzinfo=timezone.utc)}
    assert finding_id(rule, COV_002_ROW) != finding_id(rule, next_window)
    assert finding_id(rule, COV_002_ROW) != finding_id(RULES["GENIE-COV-001"], COV_002_ROW)


def test_missing_key_column_is_an_error():
    with pytest.raises(RuleError, match="no finding_key column window_start"):
        finding_id(RULES["GENIE-COV-002"], {"workspace_id": "1"})


def test_finding_carries_rule_metadata_and_evidence():
    f = to_finding(RULES["GENIE-COV-002"], COV_002_ROW, "run-1", NOW)
    assert (f["rule_id"], f["category"], f["severity"], f["status"]) == ("GENIE-COV-002", "coverage", "medium", "new")
    assert f["workspace_id"] == "1000000000000001" and f["user_id"] == "analyst@example.com"
    assert f["first_seen"] == COV_002_ROW["first_seen"] and f["last_seen"] == COV_002_ROW["last_seen"]
    assert f["conversation_ids"] == []
    assert json.loads(f["evidence"])["requests"] == 12


def test_frameworks_are_flattened():
    row = {"user_id": "analyst@example.com", "workspace_id": "1", "day": NOW, "access_requests": 2}
    f = to_finding(RULES["GENIE-004"], row, "run-1", NOW)
    assert f["frameworks"] == ["LLM06:2025 Excessive Agency"]


def test_conversation_ids_are_kept_for_joining_upstream_sessions():
    row = {"user_id": "analyst@example.com", "workspace_id": "1", "day": NOW, "conversation_ids": ["3000000000000001", None]}
    assert to_finding(RULES["GENIE-004"], row, "run-1", NOW)["conversation_ids"] == ["3000000000000001"]


def test_finding_dict_matches_table_columns():
    columns = [c.split()[0] for c in FINDING_COLUMNS.split(", ")]
    assert list(to_finding(RULES["GENIE-COV-002"], COV_002_ROW, "run-1", NOW)) == columns


@pytest.mark.parametrize("rule", RULES.values(), ids=lambda r: r.id)
def test_finding_key_columns_are_in_the_rule_output(rule):
    for column in rule.finding_key:
        assert re.search(rf"\b{column}\b", rule.sql), f"{rule.id}: finding_key column {column} not in SQL"
