# v0.1.0-alpha — experimental prerelease

Python distribution version: **0.1.0a1**. Intended Git tag: **v0.1.0-alpha**.
This is an experimental CLI alpha, **not production-ready** and not independently
security-audited. GitHub prerelease assets are the wheel, built source archive and
SHA256SUMS; no package registry publication is performed.

SafeShell inspects commands without executing the submitted command, applies
strict offline policies, runs permitted commands inside a fail-closed Linux
Bubblewrap/seccomp configuration, and stores local decision/exit metadata.
Risk predictions do not change kernel restrictions. Approval cannot override
hard denials or missing enforcement. No GUI, AI features or extra backend exists.

## Try this release

Follow [the complete fresh Ubuntu VirtualBox guide](docs/VIRTUALBOX.md), then
[the five-minute friend walkthrough](docs/FRIEND_TESTING.md). Install the verified
wheel in a fresh venv; version must be 0.1.0a1 and doctor must succeed before
protected execution. Ubuntu 24.04 needs the documented scoped AppArmor test-host
policy on the validated configuration; global restrictions stay enabled.
Native Windows/macOS provide inspection/policy/history and refuse execution.

## Important limitations

- **Workspace files can be read, changed or deleted**, including mounted secrets.
  Use private disposable copies without concurrent host writers. Generated outputs
  can be malicious. Checking/scanning/binding is not atomic.
- Runtime code and some kernel/proc metadata remain readable. There is no whole
  host root bind, but this is not a VM secrecy boundary or immutable runtime image.
- Wall-time and combined-output caps exist (defaults 300s / 1 MiB). **No CPU,
  memory, process-count or disk quotas** are enforced. Resource exhaustion remains possible.
- Fixed shell/core/Python runtime only; no Git, curl, npm/Node or arbitrary SDKs.
  Interactive input, network-enabled policies and unsupported shell grammar are refused.
- Host kernel/runtime trust, same-UID host races and unsigned local history remain.
  Linux arm64/other filesystems/alternate ABIs and Windows history ACLs are unverified.
- There is **no independent security audit** or claim that all vulnerabilities are found.

## Validation and public review

[VALIDATION.md](docs/VALIDATION.md) records actual native Ubuntu and portable CI,
separate from earlier local WSL/Debian checkpoints. The final prerelease body
records the tagged SHA, successful final CI URL and exact uploaded asset hashes.
The [public-readiness review](docs/PUBLIC_REVIEW.md) covers reachable history,
temporary-helper exclusion and remaining verification limits.

Release preparation also tightens portable unexpected-skip rejection, checks
distribution/source equality and required guide contents, tests the installed
dummy boundary/cleanup walkthrough, and includes issue/security reporting guidance.
Prior CI fixes retained NNP, minimal mounts, network separation, seccomp and
fail-closed behavior. No security check was removed to obtain a green run.
