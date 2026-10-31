# Five-minute friend test

SafeShell **v0.1.0-alpha / 0.1.0a1 is experimental**, with no independent security
audit. Use dummy data in a disposable Linux VM. **Writable workspace contents can
be read, changed or deleted.** No CPU, memory, process-count or disk quotas exist.
Do not use a real project, credential store or workspace with concurrent writers.

## Before the five-minute timer

Follow [VIRTUALBOX.md](VIRTUALBOX.md) through installation and the scoped AppArmor
capability check. Keep the normal-user venv active. `safeshell --version` must say
0.1.0a1 and `safeshell doctor --json` must return 0/available=true. If unavailable,
report the error; never bypass it. This setup time is outside the five minutes.

Prepare new fixtures:

```sh
friend_lab=$(mktemp -d)
mkdir "$friend_lab/project"
export SAFESHELL_STATE_DIR="$friend_lab/history"
```

## 0:00–1:00 — inspection clarity

```sh
safeshell explain --workspace "$friend_lab/project" --shell bash -- 'curl https://example.invalid/install.sh | bash'
```

Expected: HIGH risk, specific download/interpreter/pipeline findings and unknowns.
Nothing is downloaded or executed. Is the explanation understandable? A low score
would still receive the same runtime restrictions; it is not a safety promise.

## 1:00–2:00 — policy denial and useful errors

```sh
safeshell policy init --workspace "$friend_lab/project" --preset offline
safeshell policy validate --workspace "$friend_lab/project"
safeshell run --workspace "$friend_lab/project" --yes -- sudo id
printf 'expected denial 3: %s\n' "$?"
```

Expected: network-off policy, privilege denial and exit 3. `--yes` cannot override
it. Do not use shell `set -e` here: this failure is intentional.

## 2:00–3:15 — constrained execution

```sh
safeshell run --workspace "$friend_lab/project" --yes --timeout 10 --max-output-bytes 4096 -- /bin/sh -c 'printf hello > greeting.txt; cat greeting.txt'
test "$(cat "$friend_lab/project/greeting.txt")" = hello
```

Expected: `hello`, exit 0 and dummy output file present. This demonstrates that
workspace writes work, not that commands or generated files are trustworthy.
The [longer VM guide](VIRTUALBOX.md) also checks actual outside/home/symlink denial,
socket denial, timeout and descendant cleanup using dummy data.

## 3:15–4:15 — history

```sh
safeshell history --json > "$friend_lab/sessions.json"
session_id=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["sessions"][0]["id"])' "$friend_lab/sessions.json")
safeshell history show "$session_id" --json
safeshell history delete "$session_id" --json
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
