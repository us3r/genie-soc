"""Run every enabled rule and MERGE the results into the findings table.

Entry point for the scheduled job (a serverless spark_python_task). Table locations come from
job parameters, so the same code runs against any metastore. A failing rule does not stop the
others: its error goes to rule_runs and the run fails at the end, so the job alerts on it.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path



def _bundle_root() -> Path:
    # Serverless spark_python_task runs the file through exec(), so __file__ is undefined there.
    if "__file__" in globals():
        return Path(__file__).resolve().parents[2]
    if "--bundle-root" in sys.argv:
        return Path(sys.argv[sys.argv.index("--bundle-root") + 1])
    raise SystemExit("pass --bundle-root when __file__ is not defined")


ROOT = _bundle_root()
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from genie_soc.findings import (  # noqa: E402
    FINDING_COLUMNS,
    FINDINGS_DDL,
    RULE_RUNS_DDL,
    SUPPRESSIONS_DDL,
    to_finding,
)
from genie_soc.rules import load_rules, render_sql  # noqa: E402

RULE_RUN_COLUMNS = (
    "run_id string, rule_id string, rule_version int, started_at timestamp, "
    "duration_ms bigint, status string, rows_returned int, error string"
)

MERGE_FINDINGS = """
MERGE INTO {findings} t
USING new_findings s
ON t.finding_id = s.finding_id
WHEN MATCHED THEN UPDATE SET
  t.first_seen = least(t.first_seen, s.first_seen),
  t.last_seen = greatest(t.last_seen, s.last_seen),
  t.updated_at = s.updated_at,
  t.times_seen = t.times_seen + 1,
  t.rule_version = s.rule_version,
  t.run_id = s.run_id,
  t.evidence = s.evidence,
  t.conversation_ids = array_sort(array_distinct(concat(
    coalesce(t.conversation_ids, array()), coalesce(s.conversation_ids, array()))))
WHEN NOT MATCHED THEN INSERT *
"""

APPLY_SUPPRESSIONS = """
MERGE INTO {findings} t
USING (
  SELECT f.finding_id, min(s.suppression_id) AS suppression_id
  FROM {findings} f
  JOIN {suppressions} s
    ON (s.rule_id IS NULL OR s.rule_id = f.rule_id)
   AND (s.workspace_id IS NULL OR s.workspace_id = f.workspace_id)
   AND (s.user_id IS NULL OR s.user_id = f.user_id)
   AND (s.expires_at IS NULL OR s.expires_at > current_timestamp())
  WHERE f.status = 'new'
  GROUP BY f.finding_id
) m
ON t.finding_id = m.finding_id
WHEN MATCHED THEN UPDATE SET t.status = 'suppressed', t.suppression_id = m.suppression_id
"""


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-table", required=True)
    parser.add_argument("--audit-table", default="system.access.audit")
    parser.add_argument("--assistant-events-table", default="system.access.assistant_events")
    parser.add_argument("--genie-services", default="Genie One,genie-code-agent")
    parser.add_argument("--output-schema", required=True, help="catalog.schema for genie-soc tables")
    parser.add_argument("--bundle-root", default=str(ROOT))
    parser.add_argument("--rules-dir", default=str(ROOT / "rules"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    from pyspark.sql import SparkSession

    spark = SparkSession.builder.getOrCreate()
    findings_table = f"{args.output_schema}.findings"
    suppressions_table = f"{args.output_schema}.suppressions"
    rule_runs_table = f"{args.output_schema}.rule_runs"
    for ddl, table in (
        (FINDINGS_DDL, findings_table),
        (SUPPRESSIONS_DDL, suppressions_table),
        (RULE_RUNS_DDL, rule_runs_table),
    ):
        spark.sql(ddl.format(table=table))
    add_missing_columns(spark, findings_table, FINDING_COLUMNS)

    environment = {
        "trace_table": args.trace_table,
        "audit_table": args.audit_table,
        "assistant_events_table": args.assistant_events_table,
        "genie_services": [s.strip() for s in args.genie_services.split(",") if s.strip()],
    }
    run_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    findings: dict[str, dict] = {}
    runs: list[tuple] = []

    for rule in load_rules(args.rules_dir):
        if rule.status == "disabled":
            continue
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()
        try:
            rows = [r.asDict(recursive=True) for r in spark.sql(render_sql(rule, environment)).collect()]
            for row in rows:
                finding = to_finding(rule, row, run_id, now)
                findings[finding["finding_id"]] = finding
            runs.append((run_id, rule.id, rule.version, started, _ms(t0), "ok", len(rows), None))
            print(f"{rule.id}: {len(rows)} rows")
        except Exception as exc:  # one broken rule must not hide the others
            runs.append((run_id, rule.id, rule.version, started, _ms(t0), "error", None, str(exc)[:4000]))
            print(f"{rule.id}: ERROR {exc}", file=sys.stderr)

    columns = [c.split()[0] for c in FINDING_COLUMNS.split(", ")]
    if findings:
        rows = [tuple(f[c] for c in columns) for f in findings.values()]
        spark.createDataFrame(rows, FINDING_COLUMNS).createOrReplaceTempView("new_findings")
        spark.sql(MERGE_FINDINGS.format(findings=findings_table))
    spark.sql(APPLY_SUPPRESSIONS.format(findings=findings_table, suppressions=suppressions_table))
    spark.createDataFrame(runs, RULE_RUN_COLUMNS).write.mode("append").saveAsTable(rule_runs_table)

    failed = [r[1] for r in runs if r[5] == "error"]
    print(f"run {run_id}: {len(runs)} rules, {len(findings)} findings, {len(failed)} failed")
    if failed:
        raise RuntimeError(f"rules failed: {', '.join(failed)}; see {rule_runs_table}")


def add_missing_columns(spark, table: str, columns: str) -> None:
    """Add columns introduced after the table was created; Delta keeps existing rows as NULL."""
    existing = set(spark.table(table).columns)
    for column in columns.split(", "):
        name, dtype = column.split(" ", 1)
        if name not in existing:
            spark.sql(f"ALTER TABLE {table} ADD COLUMNS ({name} {dtype})")


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


if __name__ == "__main__":
    main()
