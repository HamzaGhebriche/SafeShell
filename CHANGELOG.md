# Changelog

## 0.1.0-alpha.2 (Python 0.1.0a2) — 2026-11-25

Experimental GitHub prerelease. No PyPI publication, production-support or
independent-audit claim. The original v0.1.0-alpha release and assets are unchanged.

* Add `inspect <local-repo>`, `map <local-repo>` and `findings <local-repo>` with
  concise text output, `--format json`/`--json`, `--verbose` and `--show-map`.
* Add bounded static inventory, literal execution paths, graph export, normalized
  offline Trivy/OSV evidence, transitive CVE/alias deduplication and explainable
  correlations. Inspection never launches target code or installation scripts.
* Keep incomplete analysis explicit: UNKNOWN and scanner PARTIAL/UNAVAILABLE/
  DISABLED states, including `--disable-scanner`. CLI 0 means report generated,
  never permission to execute. LOW RISK is not a safety guarantee.
* Correct graph edges inferred from comments/data, mixed manual/automatic
  evidence, guessed cwd, npm chains, file/line attribution, Python ecosystem
  deduplication, malformed scanner fields and PowerShell UTF-16/BOM handling.
* Preserve existing explain/run/policy/history/doctor behavior and Linux sandbox
  restrictions. External scanners remain outside that execution sandbox;
  YARA-X and Scorecard remain feature-gated, not operational integrations.
* Add controlled benchmark fixtures, regression and strict nested-package archive
  checks. A synthetic benchmark does not establish general reliability.
* Verify wheel and built sdist installations in separate fresh venvs, with
  explicit offline source-build dependencies and CI-built release artifacts.

See [inspection limits](docs/INSPECTION.md) and the historical
[implementation review](docs/INSPECTION_REVIEW.md). Exact release-commit CI,
artifact hashes and post-publication checks are recorded in the GitHub release.

## 0.1.0-alpha — candidate 1 (Python 0.1.0a1)

Experimental alpha, prepared for review on 2026-10-30; public GitHub prerelease
authorized on 2026-10-31. No production-support or independent-audit claim.

* CLI inspection, deterministic findings, strict offline policies, local metadata history,
  versioned JSON and Linux bubblewrap/libseccomp execution.
* Whole host runtime-tree mounts replaced by explicit distro executable, ELF dependency and
  packaged Python stdlib files. Host startup customizations/site packages excluded.
* Configurable wall-time and combined-output limits; independent timeout watchdog, bounded
  output draining, explicit limit termination status and descendant cleanup tests.
* Fail-closed unsupported syntax/policy/enforcement handling; no host fallback. Unsupported
  filesystem-write denial rejected rather than pretending it changes the workspace mount.
* Real zero-skip WSL and native Debian VM suites, namespace/runtime inventories, fresh-venv
  offline wheel workflow verifier, source/wheel distributions and CI release checks.
* Final review: reject non-regular history records, discover the complete test directory,
  verify installed hard denials, and prepare a five-minute walkthrough and tester checklist.

Native Ubuntu CI passed 95 tests with zero skips and real installed-wheel workflows;
the portable Ubuntu/Windows/macOS matrix passed. [Commit/run/evidence](docs/VALIDATION.md).
CI follow-up pins Ruff, requires the declared setuptools minimum, resolves macOS path aliases,
and loads a scoped AppArmor setup/stacked-guest policy without disabling NNP or the global
user-namespace restriction. The timeout cleanup fixture retains readiness/no-write controls
with startup headroom. Those results describe the earlier private checkpoint.

Public preparation adds strict portable skip checks, README/package metadata,
distribution/source checks and retained CI build assets, installed dummy-boundary
and timeout-cleanup demonstrations, a complete VirtualBox guide, a five-minute
friend guide and issue/security-reporting templates. Reachable history and the
untracked temporary GitHub helper were reviewed before public visibility.
No package registry publication is performed.

No CPU/memory/process/disk quotas, immutable runtime image,
concurrent host-writer protection, cross-platform enforcement, independent audit or production
readiness is claimed. Workspace data and exposed runtime code remain readable.
