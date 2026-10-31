# Architecture

`cli.py` owns argument handling, terminal rendering, approval and orchestration.
`analysis.py` owns the quote-aware lexer, recursive-descent shell grammar, typed commands and
findings, and deterministic rules. `policy.py` validates strictly typed TOML and computes a
pure decision from a report and policy. `backend.py` owns platform probing, canonical workspace
checks, seccomp generation and bubblewrap lifecycle. `runtime.py` selects individual system
code mounts using trusted ELF metadata and distro manifests without executing discovery programs.
It does not parse workspace executables or replace kernel enforcement. `audit.py` stores minimal local records
and escapes untrusted display text. There are no cloud integrations or implicit host launchers.

Flow: parse CLI → resolve workspace → load/validate policy → inspect → evaluate → probe backend
→ audit decision → require approval where applicable → verify workspace again → launch exact
argv in bubblewrap → record exit. Inspection stops before audit/launch. Missing enforcement
never routes to a host subprocess. The only host subprocesses are the trusted bubblewrap binary
for a fixed capability probe and for sandbox setup.

The public report uses schema_version 1. Predicted behavior/findings, configured policy,
backend probe result, configured restrictions and observed exit result are separate fields.
`effective_enforcement` remains null in probe/preview reports; `probed_restrictions` describes
the setup configuration when the fixed true command succeeds. Neither field certifies a
boundary test run or a later launch. Evidence for containment belongs in the validation artifacts.
Each launch uses the same restrictions and can still fail.
Future agent launchers and a UI should call these modules and preserve that distinction.
