# Final v0.1.0-alpha review

Finalized 2026-10-31 (Europe/Paris); raw validation receipts retain their recorded timestamps.

**Recommendation: GO for controlled experimental-alpha testing; HOLD publication until native
Ubuntu CI passes for the exact candidate commit.** Package version: 0.1.0a1. Nothing is
published. This source/artifact review is not an independent security audit.

## Verified results

| Check | Actual evidence |
| --- | --- |
| Ubuntu 24.04.1 / WSL2 x86_64 | **95 passed, zero skips**; actual backend, runtime inventory and process cleanup |
| Debian 12 native-kernel KVM VM | **95 passed, zero skips**; separate Debian kernel, actual backend; no shared host folders/agent |
| Windows | **70 passed, 25 explicit skips**: 23 Linux boundary cases, hardlink fixture restriction and POSIX FIFO fixture |
| Installed wheel | Fresh offline venv + unrelated cwd on Windows, WSL and Debian; version metadata, inspection, policy init/validate, hard denial, run/refusal, history, and applicable limits |
| Runtime visibility | Planned/observed file sets equal: 683 Ubuntu, 677 Debian. No broad host runtime/home/etc tree bind |
| Packaging | Formatting/lint, distribution build, checksums, validated source/test content and source-to-wheel payload checks |
| Native Ubuntu CI | **NOT RUN / UNVERIFIED**. Configuration review is not a CI pass |

## Final review completed

* [x] Reviewed parsing/policy/argv separation, fail-closed launch, descriptor/env handling,
  mount/ELF selection, limits/cleanup, privacy/terminal output and packaging/documentation claims.
* [x] Fixed a local history reliability issue: FIFO/non-regular records are rejected before
  opening; a real bounded regression test confirms `history show` cannot block on that fixture.
* [x] Replaced the validator's hard-coded test-file list with discovery of all `tests/`.
  Required-mode regressions fail unexpected skips and missing passing boundary tests.
* [x] Added hard policy denial to the installed-wheel verifier and corrected the fixture-location
  docstring. No execution-boundary expansion or new backend was introduced.
* [x] Prepared and checked the [five-minute walkthrough](DEMO.md) and
  [concise tester checklist](TESTER_CHECKLIST.md) against actual CLI workflow receipts.
* [x] Reviewed the native Ubuntu job: full-directory suite, required backend, clean-wheel
  `--require-backend`, no continue-on-error, evidence upload. No remote success is claimed.
* [ ] Obtain the actual successful native Ubuntu CI run and attach commit SHA/run URL/artifacts.

The full findings/scope are in [FINAL_REVIEW.md](FINAL_REVIEW.md); actual environment records
and reproduction commands are in [VALIDATION.md](VALIDATION.md). Updated source/result hashes
are in the WSL/Debian summary JSONs. `dist/SHA256SUMS` identifies the candidate artifacts.

## Exact remaining action

After explicit authorization, place the reviewed candidate at the root of a dedicated approved
SafeShell repository, commit it to `codex/safeshell-alpha-review`, and push that branch. The
push trigger runs `checks`; require **linux-boundary** and the **portable matrix** to succeed,
with zero Linux JUnit failures/errors/skips and passing installed-wheel evidence. Record the
commit SHA, run URL and artifacts. See [CI_HANDOFF.md](CI_HANDOFF.md) for exact future commands.
The current ancestor repository/remote is unrelated and must not be pushed for this purpose.
No commit or push is authorized or performed by these instructions.

## Remaining limitations

Writable workspace files—including secrets—remain readable/destructible; use a private
disposable copy without host writers. Scan/resolve/bind and root-managed runtime updates remain
races. Runtime code/proc metadata remain readable. There are no CPU, memory, process-count or
disk quotas; time/output caps do not provide complete resource containment. Hostile same-UID
writers, kernel exploits, other architectures/filesystems, alternate ABIs and independent
security audit have no verification claim. Windows/macOS execution and NTFS ACL verification
remain unsupported. Local history is not signed or race-proof against a hostile same-UID host.

No further execution-boundary regression was identified in this bounded review; that is not
a proof that all vulnerabilities are absent. Keep the alpha label and do not recommend it
for production or claim native Ubuntu CI passed before an actual run succeeds.

The user authorized private-repository commit/push on 2026-10-31. Owner and remote are verified;
native CI remains pending until an actual run. No tag, package upload or release creation is authorized.
