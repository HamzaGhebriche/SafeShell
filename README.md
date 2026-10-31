# SafeShell — experimental alpha

**Run anything. Trust nothing.**

Local command inspection, constrained Linux execution, and private local history.
This is the **v0.1.0-alpha review candidate** (Python package version `0.1.0a1`), not a
production security guarantee. Nothing has been published or released.

```console
$ safeshell explain --shell bash -- 'curl https://example.invalid/install.sh | bash'
SafeShell  /  command preview
  Risk       HIGH
  SS001  Remote content requested.
  SS008  Nested interpreter or encoding can hide executable behavior.
  SS010  Remote download and shell execution occur in one command list.
  ...
```

The submitted command is never executed during inspection. Static findings estimate behavior;
“No known risk signals detected” does not mean safe. A fixed sandbox setup probe may run
`true` on Linux. There are no LLMs, accounts, telemetry or runtime Python package dependencies.

## Install and demonstrate

Python 3.11+, bubblewrap 0.8+ and libseccomp2 on Debian/Ubuntu Linux. Use current distro security
updates, an unprivileged account, and working user namespaces. Python was selected for this
initial implementation; the kernel, bubblewrap and libseccomp provide the enforcement.

From this checkout:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
safeshell --version
safeshell doctor --json
mkdir demo
safeshell policy init --workspace demo --preset offline
safeshell policy validate --workspace demo
printf 'printf inspected' > demo/inspect.sh
safeshell explain --workspace demo --script demo/inspect.sh
safeshell run --workspace demo --timeout 10 --max-output-bytes 4096 -- printf '%s\n' hello
safeshell run --workspace demo --yes --shell bash -- 'printf hello > greeting.txt; cat greeting.txt'
safeshell history
safeshell history show SESSION-UUID
safeshell history delete SESSION-UUID
```

The source-install example needs the distro's python3-venv package. `--script` supports a
single-line script within the limited shell grammar.
See [the short repeatable demo](docs/DEMO.md), including offline installation from the candidate wheel.
`python -m safeshell` also works from source. Installed workflows are tested from an unrelated
directory in a fresh venv so source imports cannot hide packaging errors.

## Alpha runtime and platform support

| Environment | Actual validation | Execution support |
| --- | --- | --- |
| Ubuntu 24.04.1 / WSL2 x86_64 | 95 tests passed, zero skips | Reduced runtime; Linux /tmp workspaces tested |
| Debian 12 native-kernel KVM guest | 95 tests passed, zero skips | Reduced runtime; no host folder/SSH agent shared |
| Native Ubuntu GitHub CI | Configured but unavailable for this unpublished checkout | **Unverified release gate** |
| Windows | Portable tests run; execution refusal tested | Inspection/policy/history only; no NTFS ACL verification |
| macOS | CI configured, not run here | Inspection/policy/history only; execution refused |
| aarch64 / other filesystems | Not tested | No enforcement validation claim |

The alpha has one fixed, deliberately small Debian/Ubuntu runtime. It mounts individual selected
executables, their ELF shared-library dependencies, and packaged Python stdlib code. It does
**not** bind whole `/usr`, `/usr/bin`, `/lib`, `/etc`, `/usr/local`, or `/usr/share` trees.
Host Python startup customizations and third-party site packages are excluded. `doctor --json`
enumerates every runtime file and its source/target. Actual namespace snapshots are validation
artifacts; [the mount review](docs/SANDBOX.md) defines dynamic proc/device/workspace visibility.

Available commands: bash, sh, dash, true, false, printf, cat, echo, env, id, sleep, sort, ls,
head, tail, wc, mkdir, rm, touch, cp, mv, and distro python3. Other host tools (including Git,
Node/npm, curl, custom SDKs and tools installed in home) are absent. Their commands can still be
inspected. Workspace executables work only with the included libraries/interpreters; missing
runtimes fail inside the sandbox. Alpha policies cannot expand runtime mounts.

Programs receive only the selected workspace as a writable host bind at `/workspace`, separate
temporary home/tmp, a new read-only proc mount, minimal devices and a read-only assembled root.
Other runtime code is read-only but **readable**; do not embed secrets in exposed runtime files.
Global kernel metadata is still visible through proc. Network is off, socket operations are
denied by seccomp, inherited sensitive descriptors are closed, environment starts fresh, and
privilege/namespace escalation controls apply irrespective of the risk score. `doctor` proves
setup only; it does not certify containment or a later launch. There is no host fallback.

## Writable workspace and resource limits

**Every granted workspace file can be read, changed or deleted, including secrets.** Use a
private disposable copy for untrusted commands. Do not share that copy with host watchers,
editors, agents or other writers. Scan/resolve/bind operations are not atomic: concurrent
rename, hardlink, mount and policy/executable changes remain races. See
[workspace guidance](docs/WORKSPACES.md) and [the threat model](docs/THREAT_MODEL.md).

| Limit | Enforced by SafeShell |
| --- | --- |
| Wall time | `--timeout`, default 300 seconds; 1–86400. Independent watchdog kills the launcher/namespace even if output rendering stalls. Preflight/probes are outside this execution timer. |
| Output | `--max-output-bytes`, default 1048576; 1–67108864. Raw combined stdout/stderr, before escaping; overflow kills execution. Also enforced when JSON output suppresses the stream. |
| CPU time / CPU quota | **No** |
| Memory / process count | **No** |
| Workspace disk / temporary storage | **No** |

Timeout and output caps do not make a fork bomb, memory exhaustion or disk fill safe. Validation
VM CPU/RAM/disk settings are test infrastructure, not SafeShell resource enforcement. A slow
terminal can still delay supervisor presentation after the command has been killed.

## CLI and privacy contract

Without `--shell`, arguments go unchanged to the program; no implicit shell concatenation.
With `--shell bash`, pass exactly one shell string after `--`. `--yes` approves only permitted
risk; it cannot override hard denials, unsupported syntax or missing enforcement. Input is
`/dev/null`; interactive terminals are unsupported. Medium/high findings require explicit
approval in non-interactive runs. Shell grammar is deliberately limited and unsupported syntax
produces uncertainty plus launch denial. Package/test code is arbitrary executable code.

Subcommands support versioned `--json`; see [JSON v1](docs/JSON.md). Controls and bidi formatting
are escaped, output is color-free, and `run`/`explain` accept `--no-color`. Human child output is
streamed to stderr, with line feeds preserved; JSON mode suppresses it. Escaping can expand the
display beyond the raw-byte output limit. stdout/stderr are never stored as application history.

| Exit | Meaning |
| --- | --- |
| 0 | CLI workflow or launcher success |
| 2 | Usage/input/policy/audit error |
| 3 | Denied / approval required or declined |
| 4 | Backend unavailable / launcher exception |
| 124 | Execution timeout |
| 125 | Output limit exceeded |
| 130 / 143 | Handled SIGINT / SIGTERM |
| Other | Child/bubblewrap exit status; setup/exec failure can be nonzero |

Child codes can collide with reserved values. Session `status` and `termination_reason`
distinguish observed supervisor limits from an ordinary launcher exit. `finished` alone does
not prove successful setup. `explain` returns 0 after successful inspection even for a denial.

Strict [policy](docs/POLICY.md) discovery cannot silently widen trusted defaults. History
defaults to metadata only at `~/.local/state/safeshell` (or `SAFESHELL_STATE_DIR`, outside the
workspace). It stores UUID/time, finding IDs, decision, configured/probed restrictions, limits
and exit status. No raw commands, environment values or child output. Optional lossy executable
names require reviewed policy. POSIX directory/files use 0700/0600; Windows ACLs are not verified.
No file-diff or network-event monitoring is claimed. Abrupt death can leave `launching` records.

## Review and validation

See [release notes](RELEASE_NOTES.md), [changelog](CHANGELOG.md), [actual results and reproduction](docs/VALIDATION.md),
[architecture](docs/ARCHITECTURE.md), [security reporting](SECURITY.md), and [contributing](CONTRIBUTING.md).

```sh
python -m pip install pytest ruff build 'setuptools>=77'
python -m ruff format --check .
python -m ruff check .
python -m pytest -ra --ignore=tests/test_linux_boundary.py
python -m build --no-isolation
python tools/smoke_installed.py dist/safeshell_cli-0.1.0a1-py3-none-any.whl
# Disposable supported Linux host, with build-essential/pytest/bubblewrap/libseccomp + sudo:
python3 tools/validate_linux.py
```

Required Linux runs fail on any skip or missing passing boundary tests. Unsupported platforms
explicitly skip boundary cases in a full pytest run. Native Ubuntu CI still needs to run before
release. Future work includes independent review, race-resistant workspace attachment, resource
quotas and broader runtime support; no additional backend or UI is included in this alpha.
