# genie-soc

A SOC layer for Databricks Genie. It reads the Unity Gateway unified trace table, where
Genie One and Genie Code record every prompt, response and tool call, together with
`system.access.audit` and `system.access.assistant_events`, and adds what a security
operations team needs on top of content detections:

- **Coverage:** Genie used but not traced, tracing switched off, workspaces gone silent,
  turns that lost spans.
- **Agent behaviour:** access requests Genie prepares on the user's behalf, permission-denied
  bursts, new programmatic channels.
- **Detection-as-code:** one YAML file per rule, with parameterised SQL, a framework mapping
  (MITRE ATLAS, MITRE ATT&CK, OWASP Top 10 for LLM Applications) and tests against the span
  shapes of live traces.

It complements, and does not replace,
[genie-trace-monitoring](https://github.com/andyweaves/genie-trace-monitoring) by Andrew Weaver,
which detects PII, prompt injection and guardrail signals in Genie conversations. Findings
carry `conversation_ids`, which join to `conversation_id` in its `genie_sessions`. Content
detectors are imported rather than rebuilt (see [PLAN.md](PLAN.md), M3).

Status: early, experimental. A deliberately simplified, shareable picture of a production
detection-as-code flow, built and tested on an isolated lab workspace with synthetic data.
Write-up: [Who Watches the AI? What Genie Traces Actually Show](https://dere.la/posts/genie-soc-who-watches-the-ai/).

## Rules

| ID | Name | Category |
| --- | --- | --- |
| GENIE-COV-001 | Genie traces stopped arriving from a workspace | coverage |
| GENIE-COV-002 | Genie Code used but not traced | coverage |
| GENIE-COV-003 | Genie tracing switched off or redirected | coverage |
| GENIE-COV-004 | Genie Code turn lost spans | coverage |
| GENIE-001 | Genie Code permission-denied burst | detection |
| GENIE-002 | User starts using Genie One through a new programmatic channel | behaviour |
| GENIE-004 | Genie prepares an access request on the user's behalf | detection |

Every rule that reads traces is checked against `tests/fixtures/genie_spans_m0v1.json`, the span
names and attribute keys observed in live Genie traces (values synthetic). A rule that filters
on a span name, attribute or tool that real traces do not contain fails the tests.

Table locations per deployment are in `config/environments.yaml`; rule parameters can be
overridden at run time, but only with numbers, lists, intervals or table names.

## Framework sources

Rule mappings use these releases; the version is also noted above each `frameworks` block.

- [MITRE ATLAS](https://atlas.mitre.org/) 2026.10, from the [atlas-data release](https://github.com/mitre-atlas/atlas-data)
- [MITRE ATT&CK](https://attack.mitre.org/) v20.1 (enterprise); v20 retired T1562.008 in favour of
  [T1685.002](https://attack.mitre.org/techniques/T1685/002/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)

## How it runs

One Declarative Automation Bundle, one target per metastore:

- **Job `genie-soc rules`** (serverless, hourly, paused by default). `run_rules` renders every
  enabled rule, MERGEs the results into `findings` by a stable `finding_id` (the rule id plus
  the rule's `finding_key`), applies `suppressions` and logs each rule execution to
  `rule_runs`. A failing rule does not stop the others; it fails the task at the end.
- **Alert `findings to review`**, evaluated as the job's last task: one row per open finding,
  `is_new` for the latest run, coverage first. Notifications carry ids and times, never
  prompt text.

```bash
databricks bundle validate --strict -t dev -p <profile> \
  --var trace_table=<catalog>.<schema>.unity_gateway_otel_spans --var catalog=<catalog>
databricks bundle deploy -t dev -p <profile> --var ...
databricks bundle run genie_soc_rules -t dev -p <profile>
```

Keep workspace-specific values out of Git: put them in
`.databricks/bundle/<target>/variable-overrides.json`, which is ignored.

## Develop

```bash
uv run pytest
```

## Requirements on Databricks

The *Enhanced Unity AI Gateway* account preview, a unified trace table set up by a metastore
admin, and the *Genie One Tracing* / *Genie Code Tracing* previews in each monitored
workspace. Sessions opened before the previews were switched on are not traced until the page
is reloaded. See the
[Genie traces documentation](https://learn.microsoft.com/en-gb/azure/databricks/ai-gateway/genie-traces).

## License

Apache-2.0. See [NOTICE](NOTICE).
