from pathlib import Path

import pytest
import yaml

from genie_soc import RuleError, load_rule, load_rules, render_sql

ROOT = Path(__file__).resolve().parents[2]
ENV = yaml.safe_load((ROOT / "config" / "environments.yaml").read_text())["dev"]

VALID = """
id: GENIE-999
name: Test rule
version: 1
status: experimental
category: detection
severity: low
frameworks:
  owasp_llm: [LLM01:2025 Prompt Injection]
sql: SELECT * FROM {trace_table} WHERE time >= current_timestamp() - INTERVAL {lookback} AND n >= {threshold}
parameters:
  lookback: 1 HOUR
  threshold: 3
"""


def write(tmp_path: Path, text: str, name: str = "rule.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


@pytest.mark.parametrize("rule", load_rules(ROOT / "rules"), ids=lambda r: r.id)
def test_every_shipped_rule_renders(rule):
    sql = render_sql(rule, ENV)
    assert "{" not in sql and "}" not in sql
    assert ENV["trace_table"] in sql or ENV["audit_table"] in sql


def test_render_fills_environment_and_parameters(tmp_path):
    sql = render_sql(load_rule(write(tmp_path, VALID)), ENV)
    assert "FROM unity_gateway.unified_tracing.unity_gateway_otel_spans" in sql
    assert "INTERVAL 1 HOUR AND n >= 3" in sql


def test_override_replaces_parameter(tmp_path):
    sql = render_sql(load_rule(write(tmp_path, VALID)), ENV, {"threshold": 10})
    assert "n >= 10" in sql


def test_list_renders_as_escaped_literals(tmp_path):
    text = VALID.replace("{threshold}", "{threshold} AND c IN ({channels})") + "  channels: [web, \"o'brien\"]\n"
    sql = render_sql(load_rule(write(tmp_path, text)), ENV)
    assert "c IN ('web', 'o\\'brien')" in sql


@pytest.mark.parametrize(
    "override",
    [{"lookback": "1 HOUR; DROP TABLE x"}, {"threshold": "1 OR 1=1"}, {"lookback": True}],
)
def test_overrides_cannot_inject_sql(tmp_path, override):
    with pytest.raises(RuleError):
        render_sql(load_rule(write(tmp_path, VALID)), ENV, override)


def test_override_of_undeclared_parameter_is_rejected(tmp_path):
    with pytest.raises(RuleError, match="undeclared"):
        render_sql(load_rule(write(tmp_path, VALID)), ENV, {"trace_table": "other.table"})


def test_missing_placeholder_value_is_reported(tmp_path):
    rule = load_rule(write(tmp_path, VALID.replace("{threshold}", "{nope}")))
    with pytest.raises(RuleError, match="no value for nope"):
        render_sql(rule, ENV)


@pytest.mark.parametrize(
    "change, message",
    [
        (("id: GENIE-999", "id: DET-1"), "id must look like"),
        (("severity: low", "severity: urgent"), "severity"),
        (("category: detection", "category: misc"), "category"),
        (("frameworks:\n  owasp_llm: [LLM01:2025 Prompt Injection]\n", ""), "framework mapping"),
        (("version: 1\n", "version: 1\nowner: me\n"), "unknown keys owner"),
        (("name: Test rule\n", ""), "missing name"),
    ],
)
def test_invalid_rules_are_rejected(tmp_path, change, message):
    with pytest.raises(RuleError, match=message):
        load_rule(write(tmp_path, VALID.replace(*change)))


def test_coverage_rules_need_no_framework(tmp_path):
    text = VALID.replace("category: detection", "category: coverage").replace(
        "frameworks:\n  owasp_llm: [LLM01:2025 Prompt Injection]\n", ""
    )
    assert load_rule(write(tmp_path, text)).category == "coverage"


def test_duplicate_ids_are_rejected(tmp_path):
    write(tmp_path, VALID, "a.yaml")
    write(tmp_path, VALID, "b.yaml")
    with pytest.raises(RuleError, match="duplicate id GENIE-999"):
        load_rules(tmp_path)
