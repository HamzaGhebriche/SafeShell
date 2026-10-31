# JSON v1

All successful JSON documents have integer `schema_version: 1`. Usage errors emitted by
argparse before execution use standard argparse stderr/exit 2; application errors return
`{"schema_version":1,"error":"...","exit_code":2}`. Controls are JSON-escaped.

`explain --json` returns a report with:

* `mode`: argv or shell; `risk`: low, medium, high.
* `findings`: objects with id, severity, explanation, remediation, evidence, token_index
  (nullable; zero-based normalized argument index where available).
* `syntax_supported`, `predicted_behavior`, `requested_capabilities`, `unknowns`.
* `configured_policy`: all validated policy values.
* `decision`: permitted, denials, confirmation_required. This is a policy decision only.
* `backend`: available, backend, reason, configured_restrictions, effective_enforcement,
  probed_restrictions, probe_scope. `effective_enforcement` is always null in these setup/preview
  reports. `probed_restrictions` is populated when the fixed true command succeeds. This is
  setup evidence only; neither a certificate of containment nor observation of a later launch.
* `execution_permitted`: policy permission AND backend availability; approval may still be needed.

`run --json` returns `{schema_version, report, session}`. A session contains UUID `id`,
started_at/ended_at (UTC ISO 8601), command (metadata-only marker or lossy executable summary),
risk, finding IDs/severities, decision, backend, status, and exit_code. Statuses are prepared,
launching, denied, backend-unavailable, confirmation-required, cancelled, launch-failed, finished.
Alpha limit/cancellation statuses also include `timed-out`, `output-limit`, and `interrupted`.
`termination_reason` distinguishes supervisor `timeout`, `output-limit`, and `signal` from an
ordinary `launcher-exit`, even if exit integers collide. `limits` records configured wall_seconds
and output_bytes; cpu, memory, process_count and disk are null (unenforced). The output count is
raw combined child stdout/stderr before presentation, including bytes suppressed in JSON mode.
`finished` means the launcher returned; nonzero status may include setup or exec failure.
No stdout, stderr, environment values or raw command source are persisted. Audit `error`,
when present, describes launcher failure. In-memory preview JSON is intentionally detailed and
should not be logged as if it were a privacy-filtered audit record.

`doctor --json` returns schema_version and backend fields, plus `runtime_manifest` on success:
the fixed profile, selected programs, individual source/target files and inventory digest.
This manifest is not persisted in application history. `policy ... --json`
returns schema_version, valid, policy. `history --json` returns schema_version and sessions;
`history show ... --json` returns one session; delete returns schema_version and deleted UUID.
Consumers should tolerate additional fields within version 1. Breaking changes require a new
schema version. Exit-code meanings are documented in the README.
