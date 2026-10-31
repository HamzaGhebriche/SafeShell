# Exact remaining native Ubuntu CI action

Status: **configuration reviewed; remote execution unverified**. WSL and Debian VM results are
separate evidence and are not native Ubuntu GitHub CI. No remote run is recorded for this source.

Update 2026-10-31: the user explicitly authorized a normal commit/push and creating a dedicated
private repository. GitHub account **HamzaGhebriche** and the independently authenticated Git
credential account match (account ID 146950748). **HamzaGhebriche/SafeShell** was created private;
its owner, private visibility and push permission were verified. This folder now has its own
Git root and `origin=https://github.com/HamzaGhebriche/SafeShell.git`; the ancestor repository is
untouched. Staged review and the first native CI run are pending; no CI success is claimed yet.

At the earlier review, the visible Git root was `C:/Users/kali`, with an unrelated remote. Do not push this parent repository or rerun
unrelated checks and describe them as SafeShell validation.

## Action needed after explicit authorization

1. Select/create an approved dedicated SafeShell repository and a clean checkout with these
   candidate files **at the repository root**. Do not nest `.github/workflows` under SafeShell/.
2. Commit the exact reviewed candidate on `codex/safeshell-alpha-review` and authorize pushing
   that branch. These local preparation instructions do not authorize or perform that push.
3. Push the branch. The existing `push` trigger starts the `checks` workflow; opening a PR also
   triggers it. No package/release publishing step exists in this workflow.
4. Require **linux-boundary** and the **portable matrix** to finish successfully. Record the
   candidate commit SHA, workflow run URL, job results and evidence artifact before sign-off.

Suggested future commands, only in that approved dedicated checkout:

```sh
test "$(git rev-parse --show-toplevel)" = "$PWD" || exit 1
git switch -c codex/safeshell-alpha-review
git add -- .github .gitignore pyproject.toml MANIFEST.in LICENSE README.md CHANGELOG.md RELEASE_NOTES.md SECURITY.md CONTRIBUTING.md Vagrantfile safeshell tests tools docs examples
git commit -m 'Prepare SafeShell v0.1.0-alpha review candidate'
# Only after the separate push authorization and remote check:
git remote -v
git push -u origin codex/safeshell-alpha-review
```

## What the reviewed Ubuntu job actually requests

`.github/workflows/ci.yml` selects `ubuntu-24.04`, read-only contents permission, a 15-minute
job timeout and `SAFESHELL_REQUIRE_BACKEND=1`. It installs distro backend/compiler/venv prerequisites,
runs `tools/validate_linux.py`, builds the distribution, and runs the wheel's fresh-venv smoke
workflow with `--require-backend`. It uploads `linux-enforcement-evidence` even after failure.
There is no `continue-on-error`, host fallback, backend mocking or skip acceptance in this job.

The validator discovers **all of `tests/`**, including the entire boundary file. Its pytest
session gate fails on any skipped test or no passing boundary cases. Gate subprocess regressions
cover skipped/no-boundary runs. The installed-wheel verifier requires a real available backend,
checks version metadata and source-import exclusion, and exercises inspection/script, strict
policy denial, protected run, history, timeout and output-limit results.

Accept only actual artifacts with zero JUnit failures/errors/skips, all collected tests present,
backend available, planned/observed runtime inventories equal, and installed smoke version
0.1.0a1 plus expected denial/limit exit codes. A fixture/setup failure is a failed run, never a
substitute for skipped security tests. Keep environment versions and artifact hashes tied to
that commit. Do not label native Ubuntu CI passed from configuration inspection alone.
