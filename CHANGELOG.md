# Changelog

## 0.1.0-alpha — candidate 1 (Python 0.1.0a1)

Experimental, local and unpublished. Prepared for review on 2026-10-30.

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

Native Ubuntu CI is unverified. No CPU/memory/process/disk quotas, immutable runtime image,
concurrent host-writer protection, cross-platform enforcement, independent audit or production
readiness is claimed. Workspace data and exposed runtime code remain readable.
