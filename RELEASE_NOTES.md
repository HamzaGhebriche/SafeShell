# v0.1.0-alpha review candidate

**Experimental alpha. Not published. Not a production security boundary certification.**
The distribution version is `0.1.0a1`; this is the first review candidate for the human-facing
v0.1.0-alpha label. No tag, hosted release, package upload, commit or push was created.

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

Validation: 95 tests passed without skips on Ubuntu/WSL and a separate Debian native-kernel KVM
guest. Native Ubuntu CI cannot run for this unpublished standalone folder inside an unrelated
parent repository; that is a remaining release gate. See [actual evidence](docs/VALIDATION.md),
[filesystem inventory](docs/SANDBOX.md), and [the demonstration](docs/DEMO.md).

Review artifacts are the alpha wheel/source archive under `dist/`, their SHA256SUMS, current
validation summaries, runtime/namespace snapshots and clean-install workflow reports. Builds
are local; hashes identify the exact reviewed bytes, not reproducible-build certification.

Before any publication: complete native Ubuntu CI for the exact source, review the runtime/ELF
resolver and resource-lifecycle changes, inspect artifacts, and acknowledge documented races,
kernel trust, filesystem/platform scope and resource gaps. Independent review remains desirable;
no independent security audit has been completed.
