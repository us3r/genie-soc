"""Rules must reference span names, attributes and audit fields that exist in real data.

Both rules written from the documentation alone matched nothing in live traces: the Genie One
root span is `invoke_agent GenieOne`, not `invoke_agent OneChat`, and Genie Code tool spans
are `execute_tool <tool>`, not `tool.execute:<tool>`. The fixture records the shapes observed
in live traces (values synthetic), and these tests fail when a rule drifts away from them.
"""

import json
import re
from pathlib import Path

import pytest

from genie_soc import load_rules

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((ROOT / "tests" / "fixtures" / "genie_spans_m0v1.json").read_text())
SPANS = FIXTURE["spans"]
AUDIT = FIXTURE["audit_events"]
ASSISTANT = FIXTURE["assistant_events"]
RULES = load_rules(ROOT / "rules")

ATTRIBUTE = re.compile(r"attributes:\['([^']+)'\]")
SPAN_NAME = re.compile(r"\bname\s+(=|LIKE)\s+'([^']+)'")
TOOL_NAME = re.compile(r"attributes:\['gen_ai\.tool\.name'\]::string\s*=\s*'([^']+)'")
REQUEST_PARAM = re.compile(r"request_params\['([^']+)'\]")
USER_AGENT = re.compile(r"user_agent\s+LIKE\s+'([^']+)'")


def like_to_regex(pattern: str) -> re.Pattern:
    return re.compile("^" + re.escape(pattern).replace("%", ".*").replace("_", ".") + "$")


def uses(rule, source: str) -> bool:
    return source in rule.data_sources


trace_rules = [r for r in RULES if uses(r, "unified_trace_table")]
audit_rules = [r for r in RULES if uses(r, "system.access.audit")]
assistant_rules = [r for r in RULES if uses(r, "system.access.assistant_events")]


@pytest.mark.parametrize("rule", trace_rules, ids=lambda r: r.id)
def test_attributes_exist_in_real_spans(rule):
    known = {key for span in SPANS for key in span["attributes"]}
    missing = set(ATTRIBUTE.findall(rule.sql)) - known
    assert not missing, f"{rule.id} reads attributes never seen in Genie spans: {sorted(missing)}"


@pytest.mark.parametrize("rule", trace_rules, ids=lambda r: r.id)
def test_span_names_match_real_spans(rule):
    names = [span["name"] for span in SPANS]
    for op, value in SPAN_NAME.findall(rule.sql):
        pattern = like_to_regex(value) if op == "LIKE" else re.compile("^" + re.escape(value) + "$")
        assert any(pattern.match(n) for n in names), f"{rule.id}: name {op} '{value}' matches no real span"


@pytest.mark.parametrize("rule", trace_rules, ids=lambda r: r.id)
def test_tool_names_match_real_spans(rule):
    tools = {span["attributes"].get("gen_ai.tool.name") for span in SPANS}
    unknown = set(TOOL_NAME.findall(rule.sql)) - tools
    assert not unknown, f"{rule.id} filters on tools never seen in Genie spans: {sorted(unknown)}"


@pytest.mark.parametrize("rule", audit_rules, ids=lambda r: r.id)
def test_audit_fields_match_real_events(rule):
    params = {key for event in AUDIT for key in event["request_params"]}
    missing = set(REQUEST_PARAM.findall(rule.sql)) - params
    assert not missing, f"{rule.id} reads request_params never seen in audit events: {sorted(missing)}"
    for prefix in USER_AGENT.findall(rule.sql):
        pattern = like_to_regex(prefix)
        assert any(pattern.match(e["user_agent"]) for e in AUDIT), f"{rule.id}: user_agent LIKE '{prefix}' matches nothing"


def test_contract_checks_catch_the_documented_names():
    names = [span["name"] for span in SPANS]
    assert not any(like_to_regex("tool.execute:%").match(n) for n in names)
    assert "invoke_agent OneChat" not in names


@pytest.mark.parametrize("rule", assistant_rules, ids=lambda r: r.id)
def test_assistant_event_fields_match_real_events(rule):
    for column in ("workspace_id", "event_time", "initiated_by", "user_agent"):
        assert column in ASSISTANT[0], f"fixture lacks {column}"
    for prefix in USER_AGENT.findall(rule.sql):
        pattern = like_to_regex(prefix)
        assert any(pattern.match(e["user_agent"]) for e in ASSISTANT), f"{rule.id}: user_agent LIKE '{prefix}' matches nothing"
