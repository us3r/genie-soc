"""Turn rule result rows into findings with stable ids.

A rule runs every hour over a window wider than the schedule, so the same incident comes back
on every run. The finding id is a hash of the rule id and the rule's finding_key columns: the
runner MERGEs on it, so a repeat updates the existing finding instead of adding a new one.

Findings carry identifiers, counts and times, never prompt or response text. Everything else
a rule returns goes into `evidence` as JSON for the analyst.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from genie_soc.rules import Rule, RuleError

FINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
  finding_id STRING NOT NULL COMMENT 'sha256 of rule id and finding_key values',
  rule_id STRING NOT NULL,
  rule_version INT,
  rule_name STRING,
  category STRING,
  severity STRING,
  frameworks ARRAY<STRING>,
  workspace_id STRING,
  user_id STRING,
  conversation_ids ARRAY<STRING> COMMENT 'Genie conversations involved; join to upstream genie_sessions.conversation_id',
  first_seen TIMESTAMP COMMENT 'Earliest event time reported by the rule',
  last_seen TIMESTAMP COMMENT 'Latest event time reported by the rule',
  detected_at TIMESTAMP NOT NULL COMMENT 'When the runner first produced this finding',
  updated_at TIMESTAMP NOT NULL,
  times_seen INT NOT NULL COMMENT 'Runs that returned this finding',
  status STRING NOT NULL COMMENT 'new, suppressed, triaged, closed',
  suppression_id STRING,
  run_id STRING,
  evidence STRING COMMENT 'Rule result row as JSON; never prompt or response text'
) COMMENT 'genie-soc findings, one row per incident, de-duplicated by finding_id'
"""

SUPPRESSIONS_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
  suppression_id STRING NOT NULL,
  rule_id STRING COMMENT 'NULL matches every rule',
  workspace_id STRING COMMENT 'NULL matches every workspace',
  user_id STRING COMMENT 'NULL matches every user',
  reason STRING NOT NULL,
  created_by STRING NOT NULL,
  created_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP COMMENT 'NULL never expires'
) COMMENT 'genie-soc suppressions: new findings that match are marked suppressed, not dropped'
"""

RULE_RUNS_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
  run_id STRING NOT NULL,
  rule_id STRING NOT NULL,
  rule_version INT,
  started_at TIMESTAMP NOT NULL,
  duration_ms BIGINT,
  status STRING NOT NULL COMMENT 'ok or error',
  rows_returned INT,
  error STRING
) COMMENT 'genie-soc rule executions: a rule that stops running is a coverage gap too'
"""

# Column order of the findings table, for building DataFrames from to_finding() dicts.
FINDING_COLUMNS = (
    "finding_id string, rule_id string, rule_version int, rule_name string, category string, "
    "severity string, frameworks array<string>, workspace_id string, user_id string, "
    "conversation_ids array<string>, first_seen timestamp, last_seen timestamp, detected_at timestamp, updated_at timestamp, "
    "times_seen int, status string, suppression_id string, run_id string, evidence string"
)

_FIRST_SEEN = ("first_seen", "event_time", "window_start", "hour", "time")
_LAST_SEEN = ("last_seen", "event_time", "window_start", "hour", "time", "last_trace_time", "first_seen")


def finding_id(rule: Rule, row: dict[str, Any]) -> str:
    missing = [c for c in rule.finding_key if c not in row]
    if missing:
        raise RuleError(f"{rule.id}: result has no finding_key column {', '.join(missing)}")
    key = [rule.id] + [_text(row[c]) for c in rule.finding_key]
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()


def to_finding(rule: Rule, row: dict[str, Any], run_id: str, now: datetime) -> dict[str, Any]:
    return {
        "finding_id": finding_id(rule, row),
        "rule_id": rule.id,
        "rule_version": rule.version,
        "rule_name": rule.name,
        "category": rule.category,
        "severity": rule.severity,
        "frameworks": [m for mappings in rule.frameworks.values() for m in mappings],
        "workspace_id": _optional_text(row.get("workspace_id")),
        "user_id": _optional_text(row.get("user_id")),
        "conversation_ids": [_text(c) for c in row.get("conversation_ids") or [] if c is not None],
        "first_seen": _first(row, _FIRST_SEEN),
        "last_seen": _first(row, _LAST_SEEN),
        "detected_at": now,
        "updated_at": now,
        "times_seen": 1,
        "status": "new",
        "suppression_id": None,
        "run_id": run_id,
        "evidence": json.dumps(row, default=_text, sort_keys=True),
    }


def _first(row: dict[str, Any], names: tuple[str, ...]) -> datetime | None:
    for name in names:
        if isinstance(row.get(name), datetime):
            return row[name]
    return None


def _text(value: Any) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _optional_text(value: Any) -> str | None:
    return None if value is None else _text(value)
