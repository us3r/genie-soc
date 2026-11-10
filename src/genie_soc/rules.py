"""Load, validate and render detection-as-code rules for Genie traces.

A rule is one YAML file: metadata, framework mapping and parameterised SQL. Placeholders in
the SQL are filled from two places, in this order: the environment (where the tables live,
set per deployment) and the rule's own parameters (tunable per rule, overridable at run time).

Values are never pasted into SQL as free text. A placeholder accepts only:
  - an integer or float (thresholds),
  - a list, rendered as quoted SQL string literals ('a', 'b'),
  - a string that is either a Spark interval ("7 DAYS") or a table name ("cat.schema.table").
Anything else is rejected, so a run-time override cannot inject SQL.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CATEGORIES = {"coverage", "detection", "behaviour"}
SEVERITIES = {"low", "medium", "high", "critical"}
STATUSES = {"experimental", "active", "disabled"}
REQUIRED = ("id", "name", "version", "status", "category", "severity", "sql")

_ID = re.compile(r"^GENIE-(COV-)?\d{3}$")
_INTERVAL = re.compile(r"^\d+ (SECOND|MINUTE|HOUR|DAY|WEEK|MONTH)S?$")
_TABLE = re.compile(r"^(`[^`]+`|[A-Za-z_][\w-]*)(\.(`[^`]+`|[A-Za-z_][\w-]*)){0,2}$")


class RuleError(ValueError):
    """A rule file is invalid or cannot be rendered."""


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    version: int
    status: str
    category: str
    severity: str
    sql: str
    description: str = ""
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    data_sources: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    false_positive_notes: str = ""
    tags: list[str] = field(default_factory=list)
    path: Path | None = None

    @property
    def placeholders(self) -> set[str]:
        return {name for _, name, _, _ in string.Formatter().parse(self.sql) if name}


def load_rule(path: str | Path) -> Rule:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise RuleError(f"{path.name}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleError(f"{path.name}: expected a mapping at the top level")

    missing = [key for key in REQUIRED if key not in data]
    if missing:
        raise RuleError(f"{path.name}: missing {', '.join(missing)}")
    unknown = set(data) - (set(Rule.__dataclass_fields__) - {"path"})
    if unknown:
        raise RuleError(f"{path.name}: unknown keys {', '.join(sorted(unknown))}")

    rule = Rule(**data, path=path)
    _validate(rule)
    return rule


def load_rules(directory: str | Path) -> list[Rule]:
    rules = [load_rule(p) for p in sorted(Path(directory).glob("*.yaml"))]
    seen: dict[str, Path | None] = {}
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"duplicate id {rule.id} in {rule.path} and {seen[rule.id]}")
        seen[rule.id] = rule.path
    return rules


def render_sql(
    rule: Rule, environment: dict[str, Any], overrides: dict[str, Any] | None = None
) -> str:
    """Return the rule's SQL with every placeholder filled; raise RuleError otherwise."""
    overrides = overrides or {}
    unknown = set(overrides) - set(rule.parameters)
    if unknown:
        raise RuleError(f"{rule.id}: override for undeclared parameters {', '.join(sorted(unknown))}")

    values = {**environment, **rule.parameters, **overrides}
    missing = rule.placeholders - set(values)
    if missing:
        raise RuleError(f"{rule.id}: no value for {', '.join(sorted(missing))}")

    rendered = {name: _literal(rule.id, name, values[name]) for name in rule.placeholders}
    return rule.sql.format_map(rendered)


def _validate(rule: Rule) -> None:
    where = rule.path.name if rule.path else rule.id
    if not _ID.match(rule.id):
        raise RuleError(f"{where}: id must look like GENIE-001 or GENIE-COV-001")
    if rule.category not in CATEGORIES:
        raise RuleError(f"{where}: category must be one of {sorted(CATEGORIES)}")
    if rule.severity not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {sorted(SEVERITIES)}")
    if rule.status not in STATUSES:
        raise RuleError(f"{where}: status must be one of {sorted(STATUSES)}")
    if rule.category != "coverage" and not any(rule.frameworks.values()):
        raise RuleError(f"{where}: detection and behaviour rules need a framework mapping")
    for name, value in rule.parameters.items():
        _literal(rule.id, name, value)


def _literal(rule_id: str, name: str, value: Any) -> str:
    if isinstance(value, bool):
        raise RuleError(f"{rule_id}: {name} must not be a boolean")
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        if not value or not all(isinstance(v, str) for v in value):
            raise RuleError(f"{rule_id}: {name} must be a non-empty list of strings")
        return ", ".join("'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'" for v in value)
    if isinstance(value, str) and (_INTERVAL.match(value) or _TABLE.match(value)):
        return value
    raise RuleError(f"{rule_id}: {name}={value!r} is not a number, list, interval or table name")
