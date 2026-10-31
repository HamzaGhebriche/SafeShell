# Final alpha review

Recommendation: **proceed with controlled private experimental-alpha testing**. Native Ubuntu
CI and all portable jobs actually passed on the recorded candidate commit; see VALIDATION.md.
No publication is authorized here. Production use remains outside this recommendation.
This is a source/diff and artifact review, not an independent security audit.

## Review scope and findings

The original local review had no dedicated Git baseline and compared sources with the prior
reviewed wheel. The user subsequently authorized a dedicated private repository and normal
commits/pushes. The remote follow-up reviewed those diffs, parsing → policy → launch → history
paths, runtime/ELF selection, packaging and actual CI failures. The ancestor repository was
untouched. See [repository identity and CI setup](CI_HANDOFF.md).

| Finding | Resolution / evidence |
| --- | --- |
| Non-regular history records could block `history show` by supplying a FIFO | Fixed using lstat + regular-file/size validation before opening. Real FIFO subprocess regression has a deadline so a future regression fails rather than hangs. This does not claim race-proof history against hostile same-UID writers. |
| Validator maintained an explicit list of test files | Replaced with discovery of all `tests/`; required mode rejects every skip and absence of passing boundary tests. Existing subprocess regressions exercise the rejection gate with/without terminal output. |
| Fixture docstring described /usr/local as exposed | Corrected: it is an outside dummy location that must be absent; the setuid helper uses an explicitly selected temporary workspace. |
| Installed smoke did not include the walkthrough's hard denial | Added actual `sudo id` denial with exit 3 even with --yes, including policy/decision assertions. This runs on the installed wheel, not a mocked backend. |
| Unpinned Ruff selected a newer default rule set in CI | Pinned Ruff 0.17.3 and fixed all reported imports, UTC/context management and subprocess diagnostics. No lint rules disabled; mandatory seccomp rules and fail-closed callers preserved. |
| Old preinstalled setuptools accepted by an unqualified install then failed license metadata | Both jobs explicitly require setuptools>=77, matching pyproject's declared backend requirement. Builds remain non-isolated and fail on missing prerequisites. |
| macOS temporary path aliases caused a false source-shadow assertion | Resolve temporary root and imported package paths before containment comparison. Fresh venv/unrelated cwd and source exclusion remain mandatory. |
| Native Ubuntu AppArmor denied Bubblewrap setup | Added a CI-only enforced setup/stacked-guest policy. Keep global userns restriction, NNP and all backend restrictions; verify the exact enforced guest stack before tests. No globally disabled host protection. |
| Confined inherited null descriptor metadata was denied | Scope disconnected-path metadata lookup with a synthetic child prefix. Keep actual secret-file/socket descriptor identity assertions unchanged. |
| One-second cleanup fixture could time out before guest startup | Use a five-second timeout with an eight-second descendant write delay and wait another 8.3 seconds after termination. Both readiness and no-late-write checks remain required; no skip/xfail introduced. Runtime CLI limits unchanged. |

No additional execution-boundary regression was identified in the reviewed changes. The
backend remains fail-closed; static risk never alters mounts/filtering; argv mode never becomes
an implicit host shell; missing runtime/enforcement cannot become a host command fallback.
This bounded review is not a proof that all bugs or security bypasses have been found.

## Packaging and documentation checks

The unpublished version remains 0.1.0a1 with Alpha classifier and MIT license. Source and
installed metadata must agree. Wheel tests run in an unrelated cwd/fresh venv without system
site packages. The source distribution must include runtime code, tests/gate, validation tools,
CI and review/demo docs. Final checksums identify the reviewed bytes; source-to-wheel payload
equality is checked separately from ZIP timestamps. No reproducible-build certification.

Read-only runtime files remain readable, proc exposes global metadata, writable workspace
secrets remain accessible/destructible, and concurrent host-writer races remain. The fixed
runtime excludes Git/npm/curl execution despite being able to inspect their commands. Only
wall-time/output caps are enforced; CPU/memory/process/disk quotas are absent. NTFS ACLs,
macOS execution, other architectures/filesystems and independent audit remain unverified or
unsupported. These limits are reflected in README, release notes and ALPHA_REVIEW.

See [verified results](VALIDATION.md), [CI handoff](CI_HANDOFF.md), [five-minute walkthrough](DEMO.md)
and [tester checklist](TESTER_CHECKLIST.md). Remote successes and failed setup attempts are recorded separately from earlier local validation.
