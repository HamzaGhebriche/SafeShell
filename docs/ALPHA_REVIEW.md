# Historical private-checkpoint alpha review

This document preserves the successful **earlier private checkpoint**. The user
subsequently authorized public visibility and an experimental prerelease.
Current public-readiness scope, final validation and guides are in
[PUBLIC_REVIEW.md](PUBLIC_REVIEW.md), [VALIDATION.md](VALIDATION.md),
[VIRTUALBOX.md](VIRTUALBOX.md) and [FRIEND_TESTING.md](FRIEND_TESTING.md).
No production-security certification is claimed. Version: **0.1.0a1**.

## Verified remote evidence

Repository: [HamzaGhebriche/SafeShell](https://github.com/HamzaGhebriche/SafeShell),
verified **private**, expected owner/account ID 146950748. Dedicated Git root and
origin verified; unrelated ancestor untouched. Normal commits/fast-forward pushes
preserved failed attempts and fixes. Reviewed staged text excluded credentials,
local history, temporary files and build artifacts. Nothing was force-pushed,
tagged, released or uploaded to a package registry.

Candidate **`eb621ed941f36e8d869897e2ca41d20121151776`**:
[successful checks run 41176530291](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176530291).

| Remote check | Actual result |
| --- | --- |
| Native Ubuntu 24.04 linux-boundary | **95 passed, zero failures/errors/skips**, all 23 boundary cases; actual backend, sdist/wheel and required-backend clean-wheel workflows passed |
| Portable Ubuntu | **72 passed, zero skips**; mandatory native job covers the omitted boundary file |
| Portable Windows | **71 passed, 24 explicit skips** (23 Linux boundary cases + POSIX FIFO); installed execution refusal passed |
| Portable macOS arm64 | **72 passed, 23 explicit Linux boundary skips**; installed execution refusal passed |
| All portable jobs | Lint/format, distribution build and offline fresh-venv installed workflows passed |
| Runtime/CI host policy | Exact 683-file manifest/inventory equality; `safeshell-bwrap//&safeshell-child (enforce)` observed; global AppArmor userns restriction asserted enabled |

[Artifact 13032768164](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176530291/artifacts/13032768164)
was downloaded and independently checked. JUnit confirmed 95/0, available doctor,
exact planned/observed runtime equality, installed policy-denial 3, run 0, timeout
124, output-limit 125, and successful explain/policy/history workflows. Artifact
SHA256, wheel hash, job links, source/evidence hashes and earlier failed runs are
in [validation-remote-ci.json](validation-remote-ci.json) and
[VALIDATION.md](VALIDATION.md). Raw CI artifacts expire after the stated retention.
Documentation-only follow-up commits do not alter this validated code/test/workflow
checkpoint; require their own push checks before handing off the final branch.

## Earlier local evidence — distinct checkpoints

Ubuntu/WSL2 and a separate Debian 12 native-kernel KVM guest each passed **95/0**.
Earlier Windows validation passed **70/25** (that host also denied a hardlink
fixture). Fresh installed-wheel workflows passed on all three. Those local source
and artifact hashes remain in their summary JSONs; they predate remote fixes and
are not presented as final-commit Debian/WSL reruns. macOS portable CI does not
verify Linux arm64 enforcement.

## Review and fixes

Reviewed parsing/policy/argv separation, fail-closed launch, mounts/ELF selection,
seccomp, descriptors/environment, lifecycle/limits, history/privacy and packaging.
Final local review fixed non-regular history records, complete test discovery and
installed hard-denial coverage. Remote CI then exposed real prerequisite and
portability issues: old setuptools, new Ruff defaults, macOS path aliases, and
Ubuntu AppArmor setup/NNP interactions. Fixes retained all enforcement checks;
no boundary case became skip/xfail. The timeout fixture retains readiness and
observes beyond its delayed write, with sufficient namespace-startup headroom.
See [FINAL_REVIEW.md](FINAL_REVIEW.md) for specific findings and resolutions.

Ubuntu CI loads an **application-scoped test-host policy**, not a global AppArmor
disable. Setup permissions belong to trusted Bubblewrap; guest exec stacks a
capability/userns-denying domain while retaining NNP. AppArmor file rules are not
the filesystem boundary; minimal Bubblewrap mounts and seccomp remain mandatory.
Stock Ubuntu may refuse setup without reviewed host configuration. Exact commands
and policy rationale: [CI_HANDOFF.md](CI_HANDOFF.md). This policy is not an audited
production deployment recipe.

The [five-minute walkthrough](DEMO.md) covers inspection, policy denial, protected
execution, history and native unsupported-platform refusal. The
[tester checklist](TESTER_CHECKLIST.md) covers installation clarity, explanations,
errors and reproducible sanitized bugs. Both agree with installed workflow checks.

## Remaining limitations and release decision

No remaining failure is hidden by the successful candidate run. Keep testing
private and experimental. No independent security audit has been completed.
Writable workspace secrets remain readable and files destructible; use private
disposable copies with no concurrent host writers. Resolve/scan/bind, runtime
updates and local history have same-UID host-writer races. Runtime code and some
proc/kernel metadata remain readable. No CPU, memory, process-count or disk
quotas exist; wall-time/output limits are not complete resource containment.

Kernel exploits, hostile host writers, other Linux architectures/filesystems and
alternate ABIs have no verification claim. Windows/macOS execution and NTFS ACL
verification remain unsupported. Public experimental prerelease was subsequently authorized; successful CI remains
evidence for this bounded
alpha checkpoint, not proof that all vulnerabilities are absent.
