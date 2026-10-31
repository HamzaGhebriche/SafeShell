# SafeShell — experimental alpha

Inspect an unfamiliar command before running it, apply an explicit offline policy,
and execute permitted commands inside a constrained Linux workspace. Review the
decision and exit status afterward in local metadata history.

**v0.1.0-alpha (`0.1.0a1`) is experimental. No independent security audit has been
completed. Do not use it as a production security boundary.** Every file in the
writable workspace can be **read, changed or deleted**, including secrets. Use a
disposable copy without other host writers.

## What it does

- `explain`: deterministic findings and unknowns without executing the submitted
  command. A low risk score is not a safety guarantee.
- `policy`: strict offline presets; approval never overrides a hard denial.
- `run`: Linux Bubblewrap namespaces, individual read-only runtime-file mounts,
  seccomp socket/syscall denials, fresh environment, closed sensitive descriptors,
  dropped capabilities and no-new-privileges. Setup failure never runs on the host.
- `history`: local decision/limit/exit metadata; no child output, raw command
  arguments or environment values are persisted by default.

There is no GUI, AI service, telemetry, network-enabled execution policy, additional
sandbox backend or runtime Python package dependency. Inspection cannot prove what
arbitrary code will do. See [the threat model](docs/THREAT_MODEL.md).

## Install and try it

Start with the **[complete VirtualBox guide](docs/VIRTUALBOX.md)** for a fresh
Ubuntu 24.04 LTS x86_64 guest. It includes required scoped AppArmor setup and its
reversal. Never disable AppArmor or user-namespace restrictions globally.

On a configured Debian/Ubuntu host: Python 3.11+, non-setuid Bubblewrap 0.8+,
libseccomp2, python3-venv and working unprivileged namespaces are required. Install
current distro security updates. Run SafeShell as a normal user, not root.

Download the wheel, source archive and `SHA256SUMS` from the
[experimental prerelease](https://github.com/HamzaGhebriche/SafeShell/releases/tag/v0.1.0-alpha)
into a new directory. Then:

```sh
sha256sum --check SHA256SUMS
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps safeshell_cli-0.1.0a1-py3-none-any.whl
safeshell --version
safeshell doctor --json
```

Expected version: `0.1.0a1`. Doctor must return 0 and `available: true` for protected
execution. Refusal (exit 4) means stop and diagnose prerequisites; do not bypass it.
Checksums identify downloaded bytes; they are not a digital signature or audit.

Use a **dummy-only disposable workspace**, with history outside it:

```sh
lab=$(mktemp -d)
mkdir "$lab/project"
export SAFESHELL_STATE_DIR="$lab/history"
safeshell explain --workspace "$lab/project" --shell bash -- 'curl https://example.invalid/install.sh | bash'
safeshell policy init --workspace "$lab/project" --preset offline
safeshell policy validate --workspace "$lab/project"
safeshell run --workspace "$lab/project" --yes --timeout 10 --max-output-bytes 4096 -- /bin/sh -c 'printf hello > greeting.txt; cat greeting.txt'
cat "$lab/project/greeting.txt"
safeshell history
```

Inspection flags the download/shell combination; nothing is downloaded. Protected
execution prints `hello` and writes the granted file. Child output goes to stderr;
JSON mode suppresses it. The [five-minute friend guide](docs/FRIEND_TESTING.md)
covers denial, history, expected errors and a sanitized bug-report template.

## Platform and runtime support

| Platform | Inspection / policy / history | Protected execution | Evidence |
| --- | --- | --- | --- |
| Ubuntu 24.04 x86_64 | Yes | Yes, with working namespaces and reviewed scoped AppArmor configuration | Native Ubuntu boundary CI and installed-wheel checks; [results](docs/VALIDATION.md) |
| Debian 12 x86_64 | Yes | Implemented; current host must pass doctor | Earlier separate native-kernel KVM validation; recorded source checkpoint, not a final-tag rerun |
| Ubuntu / WSL2 x86_64 | Yes | Available when the Linux kernel/backend supports it | Earlier local validation; WSL is Linux, not native Windows enforcement |
| Native Windows | Yes; NTFS history ACLs not verified | **Refused** | Portable CI and installed refusal |
| macOS, including arm64 | Yes | **Refused** | Portable CI and installed refusal; not Linux arm64 validation |
| Other Linux architectures/filesystems | No validation claim | Unverified; doctor alone is not containment verification | No release support claim |

The fixed runtime provides bash/sh/dash, true/false, printf/echo, cat, env, id,
sleep, sort, ls, head/tail/wc, mkdir/rm/touch/cp/mv and distro python3 with selected
stdlib/shared libraries. Git, curl, Node/npm, home tools, custom SDKs and third-party
Python site packages are absent. Their commands can still be inspected. Arbitrary
workspace programs need the included interpreter/libraries. Missing tools fail
inside the sandbox; policies cannot expand runtime mounts.

No broad `/usr`, `/etc`, host-home or library-tree bind is used. Runtime code is
read-only **and readable**. The writable workspace and fresh temporary home/tmp,
read-only proc and minimal devices are described in [SANDBOX.md](docs/SANDBOX.md).
Some global kernel metadata remains visible; this is not a VM secrecy boundary.

## Limits and CLI contract

| Resource | Actually enforced |
| --- | --- |
| Wall time | `--timeout`: default 300s, range 1–86400; watchdog terminates execution. Preflight/probes are outside this timer. |
| Combined raw stdout/stderr | `--max-output-bytes`: default 1 MiB, range 1 byte–64 MiB; overflow terminates execution, including JSON mode. |
| CPU / memory / process count / disk | **No SafeShell quota** |

These caps do not contain fork bombs, memory exhaustion or disk filling. Concurrent
host-writer races remain between resolving, scanning and binding a workspace;
runtime updates can also race launch. Read [WORKSPACES.md](docs/WORKSPACES.md).
Generated files may be malicious. Local history is not a signed audit trail.

Arguments after `--` are passed as argv. `--shell bash` accepts one shell string
within a deliberately limited grammar; unsupported syntax is denied. stdin is
null; interactive commands are unsupported. `--yes` approves permitted risk only.

| Exit | Meaning |
| --- | --- |
| 0 | Successful CLI workflow or child/launcher exit |
| 2 | Input, policy or local audit error |
| 3 | Policy denial / approval required or declined |
| 4 | Backend unavailable / launcher exception |
| 124 / 125 | Execution timeout / output limit |
| 130 / 143 | Handled SIGINT / SIGTERM |
| Other | Child or Bubblewrap exit |

Child codes can collide with these values; JSON `session.status` and
`termination_reason` distinguish supervisor limits from ordinary exits. A
`finished` record alone does not prove successful setup. `explain` returns 0 even
when its report predicts denial. [JSON](docs/JSON.md), [policy](docs/POLICY.md).

## Development and reporting

[Validation and actual CI](docs/VALIDATION.md) · [contributing](CONTRIBUTING.md) ·
[security reports](SECURITY.md) · [MIT license](LICENSE) · [changelog](CHANGELOG.md) ·
[release notes](RELEASE_NOTES.md) · [architecture](docs/ARCHITECTURE.md).

The complete native Linux suite must pass with zero skips. Portable CI rejects
unexpected skips and reports explicit unsupported-platform cases. Builds are
installed offline into fresh venvs from unrelated directories. Release checks
compare distribution code with the checkout and publish SHA256 checksums; no
reproducible-build or independent-audit certification is implied.
