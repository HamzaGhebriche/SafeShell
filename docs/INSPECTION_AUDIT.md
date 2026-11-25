# Repository inspection implementation audit

Baseline: existing 0.1.0a1 CLI has explain/run/policy/history/doctor. The limited
shell grammar, strict TOML policy, metadata audit store and fail-closed Linux
Bubblewrap/seccomp backend are preserved. Python 3.11+; portable inspection tests
run on Linux, Windows and macOS. Protected execution requires Linux and a working
backend; Windows/macOS cannot enforce it natively.

The original repository has 97 collected tests: 72 passed, 25 expected Windows
skips in the full suite (72 passed, 2 skipped excluding Linux boundary tests).
Ruff lint and formatting passed before modification. The default plugin-enabled
pytest run stalled; validation succeeds with PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 and
a workspace-local --basetemp. No coverage threshold or mypy configuration
exists. CI includes Ruff, pytest, build, installed-wheel smoke and a separate
required Linux enforcement job. No runtime dependencies exist.

Reuse: CLI argparse conventions, escaped text output, packaging, existing sandbox
and policies. New inspection models deliberately do not change command report v1.

Plan established before code changes: bounded inventory and normalized models;
literal execution surface parsers and graph; offline adapters against a filtered
snapshot; deduplication and explainable relationship rules; CLI; controlled
benchmark corpus; tests and documentation; full validation.

Risks: scanner parsers are an attack surface, literal references can be data,
dynamic control flow cannot be proven, mutable repositories have TOCTOU hazards,
and third-party scanners may change their flags and schemas. Inspection is not an
isolation boundary. Use an immutable/disposable copy with no concurrent writers.
