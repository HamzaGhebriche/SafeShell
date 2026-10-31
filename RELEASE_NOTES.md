# v0.1.0-alpha review candidate

**Experimental alpha. Not published. Not a production security boundary certification.**
The distribution version is `0.1.0a1`; this is the first review candidate for the human-facing
v0.1.0-alpha label. The user authorized normal commits/pushes to the dedicated private SafeShell repository.
No tag, hosted release or package upload was created; visibility remains private.

The candidate covers three workflows: inspect commands without executing them; execute within
a fail-closed Linux bubblewrap/seccomp configuration; review local metadata-only history.

The runtime is intentionally narrower than the development implementation. It no longer exposes
whole host `/usr`, library, alternatives or share trees. Supported tools are the fixed shell/
core-tool/Python set listed in README; Git, npm/Node, curl, home tools and arbitrary SDKs are not
available for execution. Missing resources fail inside the sandbox. Inspection remains usable
for commands requiring unavailable tools. Existing scripts relying on broad host runtime access
must be adapted; there is no mount-expansion flag in this alpha.

Runtime code is still readable. Host home stores and unrelated system paths are absent, but
mounted workspace secrets remain accessible and writable files can be destroyed. Use a private
disposable workspace copy with no concurrent host writers. Preflight checks are not atomic.

Execution defaults to 300 wall-clock seconds and 1 MiB combined raw stdout/stderr. The CLI can
set 1–86400 seconds and 1 byte–64 MiB. Limit exits are 124/125; JSON session termination reasons
distinguish those from ordinary child exit codes. No CPU, memory, process-count or disk quotas
are enforced. Do not treat this as complete resource containment.

Validation: native Ubuntu GitHub CI passed all 95 tests with zero skips and clean-wheel
workflows on commit `eb621ed941f36e8d869897e2ca41d20121151776`. All three portable jobs
passed, including Windows/macOS refusal. Ubuntu CI loads a scoped AppArmor policy while
retaining the global user-namespace restriction; stock Ubuntu setup may refuse execution.
Earlier local WSL and separate Debian native-kernel KVM runs each passed 95/0; those are
historical source checkpoints, not reruns of the final CI commit. See [actual evidence](docs/VALIDATION.md),
[filesystem inventory](docs/SANDBOX.md), and [the demonstration](docs/DEMO.md).

Review artifacts are the alpha wheel/source archive under `dist/`, their SHA256SUMS, current
validation summaries, runtime/namespace snapshots and clean-install workflow reports.
Local artifacts identify earlier local checkpoints; the remote CI wheel hash and evidence
are separately recorded in `docs/validation-remote-ci.json`. Hashes identify reviewed bytes,
not reproducible-build certification.

Before any publication: require successful CI on the intended final source, review the runtime/ELF
resolver and resource-lifecycle changes, inspect artifacts, and acknowledge documented races,
kernel trust, filesystem/platform scope and resource gaps. Independent review remains desirable;
no independent security audit has been completed.
