# SafeShell — experimental alpha

Inspect an unfamiliar command before running it, apply an explicit offline policy,
and execute permitted commands inside a constrained Linux workspace. Review the
decision and exit status afterward in local metadata history.

Repository trust inspection is now available as an experimental workflow:
`safeshell inspect ./repo`, `safeshell map ./repo`, and
`safeshell inspect ./repo --format json`. SafeShell correlates potential execution
paths with static security evidence before you choose whether to run code.
See [inspection, scanner setup, verdicts and limitations](docs/INSPECTION.md).
Missing scanners and incomplete coverage are reported explicitly as UNKNOWN
unless a strong correlated execution concern already warrants HIGH RISK.

**v0.1.0-alpha.2 (`0.1.0a2`) is experimental. No independent security audit has been
completed. Do not use it as a production security boundary.** Every file in the
writable workspace can be **read, changed or deleted**, including secrets. Use a
disposable copy without other host writers.

## What it does

- `inspect`, `map`, `findings`: bounded static repository inspection, potential
  execution paths and normalized evidence, with text and `inspection-1` JSON output.
  UNKNOWN means incomplete analysis. Inspection exit 0 means report generated,
  never permission to execute. External scanners are not in the execution sandbox;
  YARA-X/Scorecard remain gated. Synthetic benchmark results are not general reliability.
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

## Numbered quick start: Ubuntu 24.04 / WSL2 or a Linux guest

Run the setup steps **in order, in the same Ubuntu Bash terminal**. Stop if an
installation or capability check fails. Do not enable `set -e` for this walkthrough:
denial and limit examples intentionally return nonzero. Use dummy data only.

### 1. Identify the environment and use a regular user

```sh
uname -r
id -un
id -u
```

A kernel name containing `microsoft` / `WSL2` identifies Ubuntu running in WSL2.
That is Linux on the Windows host, **not a fresh VirtualBox guest**. A VirtualBox
guest boots its own Linux kernel, usually named `...-generic` on Ubuntu. A kernel
name without `microsoft` alone does not prove that VirtualBox is in use.

UID must be **nonzero**. SafeShell refuses protected execution as root. If you
already have a regular-user terminal, continue to step 2. Never use `sudo safeshell`.

If your terminal starts as root, first look for an existing normal login account:

```sh
getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $6, $7}'
```

Choose your existing account (with a login shell, not a service account). For
example, **replace `tester` below with that account's name**, then switch:

```sh
su - tester
```

**Only if no suitable account exists**, create one from the root terminal instead:

```sh
adduser tester
usermod -aG sudo tester
su - tester
```

These are alternative root-recovery paths, not steps to run in a normal-user
session. Continue below inside the selected user's login shell; check `id -u`
again. The sudo group permits prerequisite administration, not running SafeShell
as root. On WSL, `su -` suffices for this session; no default-user change is needed.

### 2. Install host prerequisites

Python 3.11+, non-setuid Bubblewrap 0.8+, libseccomp2 and working unprivileged
namespaces are required. Inside Ubuntu, as the normal sudo-capable user:

```sh
sudo apt-get update
sudo apt-get install -y python3 python3-venv bubblewrap libseccomp2 curl ca-certificates
```

Keep distro security updates current. Native Windows/macOS execution is unsupported;
use Ubuntu in WSL2 or a Linux guest for this walkthrough.

### 3. Download the exact alpha release and verify checksums

```sh
download_dir="$HOME/safeshell-alpha-download"
mkdir -p "$download_dir"
cd "$download_dir"
base=https://github.com/HamzaGhebriche/SafeShell/releases/download/v0.1.0-alpha.2
for asset in safeshell_cli-0.1.0a2-py3-none-any.whl safeshell_cli-0.1.0a2.tar.gz SHA256SUMS; do
  curl --fail --location --output "$asset" "$base/$asset" || exit 1
done
sha256sum --check SHA256SUMS || exit 1
tar -xzf safeshell_cli-0.1.0a2.tar.gz
src="$download_dir/safeshell_cli-0.1.0a2"
```

Expected: **both distribution files say `OK`**. Stop on a failed download or
checksum. The [prerelease](https://github.com/HamzaGhebriche/SafeShell/releases/tag/v0.1.0-alpha.2)
also lists asset hashes. Checksums identify bytes; they are not a signature or audit.
The verified source archive supplies the optional dummy fixture and scoped VM profile.
The built source archive contains the matching alpha.2 documentation and fixtures.

### 4. Install into a Python virtual environment

```sh
python3 -m venv "$HOME/safeshell-alpha-venv"
. "$HOME/safeshell-alpha-venv/bin/activate"
python -m pip install --no-index --no-deps "$download_dir/safeshell_cli-0.1.0a2-py3-none-any.whl"
safeshell --version
```

Expected version: **`0.1.0a2`**. The CLI is now available in this activated terminal.
The wheel has no runtime Python package dependencies.

### 5. Check sandbox startup without flooding the terminal

```sh
safeshell doctor --json > "$download_dir/doctor.json"
doctor_status=$?
python - "$download_dir/doctor.json" "$doctor_status" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("Availability:", d["available"])
print("Reason:", d["reason"])
print("Doctor exit code:", sys.argv[2])
PY
```

Expected: **Availability: True**, a successful setup-probe reason, and **Doctor
exit code: 0**. The large runtime inventory stays in `doctor.json`. Doctor proves
sandbox startup with a fixed command, **not containment or a later launch**.

If unavailable (normally exit 4), stop before execution. Recheck the user and
packages. **Fresh Ubuntu VirtualBox guest:** follow the
[scoped AppArmor procedure](docs/VIRTUALBOX.md#3-scoped-apparmor-setup-and-capability-check),
then repeat this step. **WSL2:** do not blindly install that VM profile. A WSL
kernel can have a different AppArmor interface; diagnose its actual availability
instead of disabling controls or assuming the VM policy applies. Never globally
disable AppArmor, NNP or user-namespace restrictions to force a pass.

### 6. Create a disposable workspace and an offline policy

```sh
lab=$(mktemp -d)
work="$lab/project"
mkdir -p "$work"
export SAFESHELL_STATE_DIR="$lab/history"
echo "Disposable workspace: $work"
safeshell policy init --workspace "$work" --preset offline
safeshell policy validate --workspace "$work"
```

Expected: `Policy valid. Network off; trusted minimum restrictions preserved.`
History is outside the workspace. Every file placed inside `$work` can be read,
changed or deleted. Do not copy real secrets or use concurrent host writers.
`policy init` creates a new file; if repeating the walkthrough, use a new `$lab`
rather than trying to initialize over an existing policy.

### 7. Get a visible working result

```sh
safeshell run --workspace "$work" --yes --timeout 10 -- /bin/sh -c 'echo SAFESHELL_OK > result.txt'
run_status=$?
echo "Execution exit code: $run_status"
cat "$work/result.txt"
```

Expected, after the session-status line:

```text
Execution exit code: 0
SAFESHELL_OK
```

Both the exit code and file content matter. If execution failed or the file is
missing, stop and read the error; do not treat a silent command as success.

### 8. Confirm a hard policy denial

```sh
safeshell run --workspace "$work" --yes -- sudo id
denial_status=$?
echo "Denial exit code: $denial_status"
```

Expected: privilege denial and **Denial exit code: 3**. `--yes` approves only
permitted risk; it cannot override hard denials or unavailable enforcement.

### 9. Inspect commands and understand the current limitation

```sh
safeshell explain --workspace "$work" --shell bash -- 'curl https://example.invalid/install.sh | bash'
explain_status=$?
echo "Explain exit code: $explain_status"
safeshell explain --workspace "$work" --shell bash -- 'curl https://example.invalid/install.sh | sudo bash'
```

`explain` **does not execute the submitted command**, though it may run the fixed
backend setup probe. Exit **0 means analysis completed**, not approval to execute.
The direct `curl ... | bash` form reports **SS010**. The released alpha currently
**misses SS010 for `curl ... | sudo bash`**, but still detects privilege and reports
policy denial. This is an inspection inconsistency, **not a demonstrated sandbox
bypass**; this documentation update does not change the application.

**Policy PERMITTED does not grant networking**: the alpha sandbox remains
network-off. It is expected that curl, Git and npm are missing inside its fixed
runtime, even though their command lines can be inspected. See the runtime list below.

### 10. List, view and delete local history

```sh
safeshell history
safeshell history --json > "$lab/sessions.json"
session_id=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["sessions"][0]["id"])' "$lab/sessions.json")
echo "Selected session: $session_id"
safeshell history show "$session_id" --json
safeshell history delete "$session_id" --json
safeshell history
```

Expected: session UUIDs and decisions/statuses; `show` displays the selected
metadata record and `delete` confirms its UUID. Other sessions remain. No child
output, environment values or raw arguments are stored by default. This is local
metadata, not a signed forensic log.

### If you reopen the terminal

Return to the **same regular user**, then reactivate the installed venv:

```sh
. "$HOME/safeshell-alpha-venv/bin/activate"
download_dir="$HOME/safeshell-alpha-download"
src="$download_dir/safeshell_cli-0.1.0a2"
```

Shell variables do not survive a new terminal. Recreate **`$lab`, `$work` and
`SAFESHELL_STATE_DIR` by repeating step 6**, then continue the tests. Reactivating
the venv alone does not recreate those variables. Do not rerun `policy init` in
an old workspace by accident. Keep the setup and each walkthrough in one terminal.

For six dummy boundary checks, timeout/cleanup, output limits and VM-specific
AppArmor verification, see [the longer guide](docs/VIRTUALBOX.md#4-disposable-workspace-dummy-home-and-permitted-execution).
WSL users may follow its common test sections, **not** its VM-only profile setup,
profile-stack assertion or reversal. The
[five-minute friend guide](docs/FRIEND_TESTING.md) starts from this installed setup.

## Platform and runtime support

| Platform | Inspection / policy / history | Protected execution | Evidence |
| --- | --- | --- | --- |
| Ubuntu 24.04 x86_64 | Yes | Yes, with working namespaces and reviewed scoped AppArmor configuration | Native Ubuntu boundary CI and installed-wheel checks; [results](docs/VALIDATION.md) |
| Debian 12 x86_64 | Yes | Implemented; current host must pass doctor | Earlier separate native-kernel KVM validation; recorded source checkpoint, not a final-tag rerun |
| Ubuntu 24.04 / WSL2 x86_64 | Yes | Manual regular-user wheel workflow succeeded; current host must pass doctor | Six dummy checks passed; reported `kernel\u0000` label does **not** verify the VM AppArmor stack |
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

[Documentation recipe validation, 2026-11-02](docs/DOCS_VALIDATION_2026-11-02.md)
records which released-wheel workflows were rerun, including the WSL label and
the inspection inconsistency. It does not claim a new VirtualBox test.

The complete native Linux suite must pass with zero skips. Portable CI rejects
unexpected skips and reports explicit unsupported-platform cases. Builds are
installed offline into fresh venvs from unrelated directories. Release checks
compare distribution code with the checkout and publish SHA256 checksums; no
reproducible-build or independent-audit certification is implied.
