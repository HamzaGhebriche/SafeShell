# Concise alpha tester checklist

Use dummy files in a private disposable project. No real credentials or destructive host tests.

* [ ] **Installation clarity:** install the candidate wheel into a fresh venv without the source
  checkout on PYTHONPATH. Version is 0.1.0a1. Linux prerequisites, fixed runtime tools and
  unsupported-platform restrictions are clear. `doctor` gives either setup details or a remedy.
* [ ] **Understandable explanations:** the walkthrough's download/shell command gets specific
  findings and unknowns without execution. “No known risk signals” is not a safety promise.
  Predicted behavior, policy permission and backend availability are distinguishable.
* [ ] **Useful errors:** `sudo id` is denied with exit 3 even with `--yes`; network-enabled policy
  is rejected; missing/unsupported enforcement refuses execution with exit 4. Invalid input
  and history IDs give useful errors. Timeout/output-limit results distinguish supervisor limits
  from ordinary child exits. Missing Git/npm/curl execution support is clearly documented.
* [ ] **History/privacy:** successful and denied fixture sessions can be listed/shown/deleted.
  Metadata-only records contain no raw arguments, environment values or child output. Treat
  local history as untrusted, not a signed audit trail.
* [ ] **Reproducible bugs:** reproduce once in a fresh fixture, preserve quoting/argument
  boundaries, and report expected versus actual behavior and exit codes using the template below.

```text
Candidate version and wheel SHA256:
OS / kernel / architecture; native host, WSL or VM:
Python and bubblewrap versions; doctor availability/reason:
Minimal fixture setup (dummy data only):
Exact command as argv, or explicit shell + one quoted command string:
Relevant policy keys and CLI limits:
Expected result / exit:
Actual result / exit:
Reproduction rate in a fresh disposable project:
Sanitized output or minimal session metadata:
```

Do not attach environment dumps, real credentials, raw private commands or whole projects.
Use [SECURITY.md](../SECURITY.md) for suspected boundary bypasses; use a normal bug report for
usability/packaging issues. An unavailable backend or unsupported runtime is not evidence of a
sandbox bypass. Actual native Ubuntu CI and portable results, commit/run links and evidence are recorded in
[VALIDATION.md](VALIDATION.md). Include the tested commit SHA as well as version in bug reports;
all candidates still use 0.1.0a1. Ubuntu hosts may need reviewed AppArmor configuration;
see [CI_HANDOFF.md](CI_HANDOFF.md).
