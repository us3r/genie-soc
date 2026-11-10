# genie-soc

A SOC layer for Databricks Genie. It reads the Unity Gateway unified trace table, where
Genie One and Genie Code record every prompt, response and tool call, and adds what a
security operations team needs on top of content detections:

- **Coverage:** which workspaces stopped sending traces, or never started.
- **Detection-as-code:** one YAML file per rule, with parameterised SQL, tests and a
  MITRE ATLAS / OWASP Top 10 for LLM Applications mapping.
- **Behaviour, evaluation, SIEM export and multi-region deployment:** see [PLAN.md](PLAN.md).

It complements, and does not replace,
[genie-trace-monitoring](https://github.com/andyweaves/genie-trace-monitoring) by Andrew Weaver,
which detects PII, prompt injection and guardrail signals in Genie conversations.

Status: early, experimental. Built and tested on synthetic data only.

## Rules

| ID | Name | Category |
| --- | --- | --- |
| GENIE-COV-001 | Genie traces stopped arriving from a workspace | coverage |
| GENIE-COV-002 | Active workspace with no Genie traces | coverage |
| GENIE-001 | Genie Code permission-denied burst | detection |
| GENIE-002 | User starts using Genie One through a new programmatic channel | behaviour |

Table locations per deployment are in `config/environments.yaml`; rule parameters can be
overridden at run time, but only with numbers, lists, intervals or table names.

## Develop

```bash
uv run pytest
```

## Requirements on Databricks

The *Enhanced Unity Gateway* account preview, a unified trace table set up by a metastore
admin, and the *Genie One Tracing* / *Genie Code Tracing* previews in each monitored
workspace. See the
[Genie traces documentation](https://learn.microsoft.com/en-gb/azure/databricks/ai-gateway/genie-traces).

## License

Apache-2.0. See [NOTICE](NOTICE).
