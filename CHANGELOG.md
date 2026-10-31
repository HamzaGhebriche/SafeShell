# Changelog

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
