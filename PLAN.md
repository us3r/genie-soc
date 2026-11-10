# genie-soc: plan

A production SOC layer for Databricks Genie, built on the Unity Gateway unified trace table.
It complements [andyweaves/genie-trace-monitoring](https://github.com/andyweaves/genie-trace-monitoring)
(content detections: PII, prompt injection, guardrail signals) with what a bank SOC also needs:
coverage, behaviour, detection-as-code, measured detector quality, multi-region and SIEM integration.

## Relationship to the upstream accelerator

| Option | Verdict |
| --- | --- |
| Fork and extend | No. A fork reads as "Andrew's project with changes" and diverges from his updates. |
| Depend on its tables | Later, optional. Its derived table schemas are not a documented contract yet. |
| **Standalone, same source** | **Yes.** Reads the documented trace table directly; can ingest upstream `genie_detections` as one more signal. |
| Separate fork for PRs | Yes, for small upstream contributions (ATLAS mapping, non-US PII recognisers). |

Rules here only use what the Databricks docs define: the unified trace table schema, Genie span
names and attributes, and `system.access.*` tables.

## Architecture

```
trace table (per metastore) ──► rules/*.yaml (detection-as-code) ──► genie_soc.findings
system.access.audit        ──►        coverage + behaviour         ──►  (OCSF view → SIEM/SOAR)
system.access.workspaces_latest                                     ──► central view (Delta Sharing,
upstream genie_detections (optional)                                      findings + metadata only)
```

- One deployment per metastore (bundle target per region). Prompt text never leaves its region.
- Findings carry IDs, scores and framework tags, never prompt text.

## Repository layout

```
rules/                  one YAML per detection (id, severity, ATLAS/OWASP mapping, parameterised SQL)
tests/rules/            rule test cases against synthetic data (true positive / true negative)
tests/unit/             local tests for the rule loader (no Spark)
src/genie_soc/          rule loader, parameter resolution, runner
src/sql/                shared views (coverage, sessions)
resources/              bundle resources (jobs, alerts)
eval/                   red-team set + MLflow evaluation of imported detectors (M3)
```

## Milestones

| # | Milestone | Done when |
| --- | --- | --- |
| M0 | Skeleton: plan, rule format, loader, unit tests, bundle config | `pytest` passes locally |
| M1 | Coverage monitoring: silent workspaces, active workspaces never traced | rules run on `dev` workspace, alert fires on a simulated gap |
| M2 | Synthetic Genie traces + rule test runner on Spark | every rule has a passing true-positive and true-negative case |
| M3 | Content detectors are imported, not rebuilt: findings from external detectors (upstream genie_detections, any prompt-injection or PII detector with a documented output table) land in `findings` as `UPSTREAM-*`, joined by `conversation_ids`; a shared red-team set measures them in MLflow | one queue for coverage, behaviour and content findings; precision/recall per imported detector |
| M4 | Behaviour: per-user baselines (volume, new tables via lineage, new channel, off-hours) | anomaly rules with tests |
| M5 | SOC integration: OCSF view, SIEM export, triage agent writing a verdict for human approval | end-to-end demo |
| M6 | Multi-region: per-region targets, central findings share | two-target deploy documented |

## Ground rules

- Isolated lab workspace and synthetic data only. No employer data, names or configuration in this repository.
- Every rule ships with tests and a framework mapping (MITRE ATLAS, OWASP Top 10 for LLM Applications).
- Upstream credit in README and NOTICE.
