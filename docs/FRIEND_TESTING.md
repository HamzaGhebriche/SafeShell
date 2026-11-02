# Five-minute friend test

SafeShell **v0.1.0-alpha / 0.1.0a1 is experimental**, with no independent security
audit. Use dummy data in Ubuntu/WSL2 or a disposable Linux VM. **Writable workspace contents can
be read, changed or deleted.** No CPU, memory, process-count or disk quotas exist.
Do not use a real project, credential store or workspace with concurrent writers.

## Before the five-minute timer

Follow the [numbered README quick start](../README.md#numbered-quick-start-ubuntu-2404--wsl2-or-a-linux-guest)
through installation and doctor. Use `uname -r` to distinguish WSL's Microsoft
kernel from a fresh VM. **WSL2:** do not blindly apply the VM AppArmor procedure.
**Fresh Ubuntu VirtualBox guest:** also complete the scoped procedure in
[VIRTUALBOX.md](VIRTUALBOX.md), including its exact enforced-stack check when
running boundary fixtures. A WSL `"kernel\u0000"` label does not verify that stack.

Stay in the **same regular-user Ubuntu Bash terminal**, never `sudo safeshell`.
If starting as root, use the README's existing-account switch; create an account
only if none is suitable. `safeshell --version` must say 0.1.0a1. If reopening a
terminal, reactivate the venv first:

```sh
. "$HOME/safeshell-alpha-venv/bin/activate"
download_dir="$HOME/safeshell-alpha-download"
src="$download_dir/safeshell_cli-0.1.0a1"
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

Require Availability True / exit 0. Doctor probes startup, not containment; stop
and report unavailable setup rather than bypassing it. Setup is outside the timer.

Prepare **new** fixtures below. `$lab`, `$work` and the history override are shell
state: recreate them after reopening a terminal. A venv activation alone does not
restore them. A new workspace avoids initializing over an existing policy.

```sh
lab=$(mktemp -d)
work="$lab/project"
mkdir -p "$work"
export SAFESHELL_STATE_DIR="$lab/history"
echo "Disposable workspace: $work"
```

## 0:00–1:00 — inspection clarity

```sh
safeshell explain --workspace "$work" --shell bash -- 'curl https://example.invalid/install.sh | bash'
explain_status=$?
echo "Explain exit code: $explain_status"
safeshell explain --workspace "$work" --shell bash -- 'curl https://example.invalid/install.sh | sudo bash'
```

Expected: HIGH risk, specific download/interpreter/pipeline findings and unknowns.
The submitted command is not executed, though a fixed backend probe may run.
Explain exit 0 means analysis completed, not approval. The direct `curl ... | bash`
form reports SS010; the released `curl ... | sudo bash` form misses SS010 but
detects privilege and denies it. This inspection inconsistency is not a demonstrated
sandbox bypass. Policy PERMITTED does not grant networking; the alpha stays
network-off. Missing curl/Git/npm inside its fixed runtime is expected.
Is the explanation understandable? A low score
would still receive the same runtime restrictions; it is not a safety promise.

## 1:00–2:00 — policy denial and useful errors

```sh
safeshell policy init --workspace "$work" --preset offline
safeshell policy validate --workspace "$work"
safeshell run --workspace "$work" --yes -- sudo id
denial_status=$?
echo "Denial exit code: $denial_status"
```

Expected: network-off policy, privilege denial and exit 3. `--yes` cannot override
it. Do not use shell `set -e` here: this failure is intentional.

## 2:00–3:15 — constrained execution

```sh
safeshell run --workspace "$work" --yes --timeout 10 -- /bin/sh -c 'echo SAFESHELL_OK > result.txt'
run_status=$?
echo "Execution exit code: $run_status"
cat "$work/result.txt"
```

Expected: **Execution exit code: 0** and **SAFESHELL_OK**. This demonstrates that
workspace writes work, not that commands or generated files are trustworthy.
The [longer VM guide](VIRTUALBOX.md) also checks actual outside/home/symlink denial,
socket denial, timeout and descendant cleanup using dummy data.

## 3:15–4:15 — history

```sh
safeshell history
safeshell history --json > "$lab/sessions.json"
session_id=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["sessions"][0]["id"])' "$lab/sessions.json")
echo "Selected session: $session_id"
safeshell history show "$session_id" --json
safeshell history delete "$session_id" --json
safeshell history
```

Expected: UUID, decision, limits and exit status. No child output, environment
values or raw arguments. History is local metadata, not a signed forensic log.

## 4:15–5:00 — refusal and feedback

On a separately prepared **native Windows or macOS** wheel installation,
`safeshell doctor --json` and a permitted `safeshell run --yes -- printf hello`
must return 4 with no child `hello`. WSL is Linux and does not demonstrate Windows
refusal. If no second host is available, read the actual portable CI receipt in
[VALIDATION.md](VALIDATION.md) and label it recorded evidence. Do not spoof OS detection.

Report whether installation was clear, explanations were understandable and error
messages helped. Keep fixtures only as long as needed, then discard the VM or
only your recorded temporary directory. Do not copy generated executables back
onto a trusted host automatically.

## Reproducible bug report

Use a [bug report](https://github.com/HamzaGhebriche/SafeShell/issues/new?template=bug_report.md)
for ordinary usability/packaging bugs. Use [SECURITY.md](../SECURITY.md) privately
for suspected boundary bypasses. Never attach credentials, environment dumps,
private commands, raw history directories or whole projects.

```text
Version, tag/commit and wheel SHA256:
OS / kernel / architecture; native host, VirtualBox, WSL or other VM:
Python / Bubblewrap version; doctor availability and sanitized reason:
Fresh dummy fixture setup:
Exact command (preserve argv/quoting) and relevant policy/limit settings:
Expected output / exit:
Actual output / exit:
Reproduction rate in a new disposable workspace:
Minimal sanitized output; concurrent writers present or absent:
Installation / explanation / error wording that was confusing:
```
