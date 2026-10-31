# Private repository and native CI handoff

The user authorized normal commits/pushes on 2026-10-31. GitHub and Git credentials
independently matched **HamzaGhebriche** (account ID 146950748). The dedicated
[HamzaGhebriche/SafeShell](https://github.com/HamzaGhebriche/SafeShell) repository
was created **private** (repository ID 1440555247). Owner, private visibility and
push permission were verified before pushing; visibility was not changed.

This checkout has its own Git root, origin
`https://github.com/HamzaGhebriche/SafeShell.git`, and branch
`codex/safeshell-alpha-review`. The unrelated ancestor repository was untouched.
Ordinary commits/fast-forward pushes preserve history. No force push, tag, hosted
release or package publication occurred. Tracked/staged text was reviewed for
credentials, history, temporary files and build artifacts. Distributions, raw
validation directories, local history and authentication helpers were excluded.

See [actual validation results](VALIDATION.md) for commit/run links and outcomes.
Earlier local WSL/Debian/Windows receipts are separate from remote GitHub CI.

## Required native job and portable matrix

`.github/workflows/ci.yml` selects `ubuntu-24.04`, read-only contents permission,
a 15-minute timeout and `SAFESHELL_REQUIRE_BACKEND=1`. It installs distro backend,
compiler, venv and AppArmor prerequisites, loads the scoped policy below, runs
`tools/validate_linux.py`, builds wheel/sdist and runs fresh-venv installed
workflows with `--require-backend`. It uploads `linux-enforcement-evidence` even
after failure. There is no continue-on-error, mocked backend, host fallback or
skip acceptance in this job.

The validator discovers **all of `tests/`**. Required-mode pytest fails on any skip
or no passing boundary cases; subprocess regressions test that gate with/without
terminal output. Inventory capture requires exact planned/observed file equality.
The installed-wheel verifier checks metadata/source-import exclusion, explain,
script, policy init/validate, hard denial, doctor, real execution, history and
timeout/output-limit exit codes. The portable Ubuntu/Windows/macOS matrix runs
lint, formatting, tests, builds and clean-wheel workflows. Matrix fail-fast is
disabled. Linux portable tests omit the boundary file because the mandatory native
job covers the complete directory. Unsupported-platform skips remain explicit.

## Ubuntu AppArmor prerequisite

Stock Ubuntu's generic unprivileged-user-namespace profile denied the capability
Bubblewrap needs to initialize loopback. The first real run failed closed. The
job does **not** disable AppArmor, change a global sysctl, remove namespaces or
seccomp, run tests as root, or substitute a container/WSL backend.

On the disposable runner it loads
[safeshell-bwrap](../.github/apparmor/safeshell-bwrap). The trusted `/usr/bin/bwrap`
setup domain permits namespace/mount assembly, capabilities and loopback lookup.
Exec **stacks** an enforced `safeshell-child` domain denying capabilities/user
namespaces. Both profiles must allow an operation; guest execs retain the
intersection. Stacking preserves no-new-privileges. The validator requires the
exact label `safeshell-bwrap//&safeshell-child (enforce)`; the setup label alone is
rejected. The workflow asserts `kernel.apparmor_restrict_unprivileged_userns=1`.

AppArmor file rules permit reachable files; they are **not** the filesystem
boundary. Explicit Bubblewrap mounts supply that boundary. Disconnected null
stdin/output pipes require metadata lookup. The child uses a distinct synthetic
disconnected-path prefix; tests still require inherited dummy secret-file/socket
identities to be absent. Seccomp, namespaces, capability dropping,
no-new-privileges and minimal mounts remain mandatory independently of this
policy. This is ephemeral test-host configuration, not an independently audited
production deployment policy. See [the kernel's no-new-privileges contract](https://docs.kernel.org/userspace-api/no_new_privs.html).

## Exact reproduction

As a nonroot sudo user on a **disposable Ubuntu 24.04 runner**:

```sh
sudo apt-get update
sudo apt-get install -y bubblewrap libseccomp2 build-essential python3-venv apparmor
sudo apparmor_parser --replace .github/apparmor/safeshell-bwrap
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
python3 -m venv .venv
. .venv/bin/activate
python -m pip install pytest ruff==0.17.3 build 'setuptools>=77'
python -m ruff check .
python -m ruff format --check .
SAFESHELL_REQUIRE_BACKEND=1 \
SAFESHELL_EXPECT_APPARMOR_PROFILE='safeshell-bwrap//&safeshell-child' \
python tools/validate_linux.py
python -m build --no-isolation
python tools/smoke_installed.py dist/safeshell_cli-0.1.0a1-py3-none-any.whl --require-backend
```

Actual tests/probes are unprivileged; only dependencies/policy and temporary
setuid/outside-dummy fixture provisioning use sudo. The validator removes its
fixtures. Destroy the disposable runner afterward; do not blindly install this
CI policy on a production host. An unconfigured host can legitimately refuse
setup in `doctor`; execution must then remain unavailable.

Subsequent authorized fixes use ordinary `git commit` then
`git push origin codex/safeshell-alpha-review`; the push trigger starts `checks`.
Require the native and all three portable jobs on the intended SHA. Inspect JUnit
failures/errors/skips and the installed-wheel receipt, not only a green badge.
