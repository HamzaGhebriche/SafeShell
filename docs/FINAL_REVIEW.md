# Final alpha review

Recommendation: **proceed with controlled experimental-alpha testing; hold publication until
native Ubuntu CI succeeds for the exact candidate commit**. No publication is authorized here.
This is a source/diff and artifact review, not an independent security audit.

## Review scope and findings

The folder has no dedicated candidate Git baseline: its visible Git root/remote belong to an
unrelated ancestor repository. The review therefore compared product sources with the prior
reviewed wheel, inspected the source/archive changes, and followed parsing → policy → launch →
history paths, runtime inventory/ELF selection, packaging metadata and CI/test entry points.

| Finding | Resolution / evidence |
| --- | --- |
| Non-regular history records could block `history show` by supplying a FIFO | Fixed using lstat + regular-file/size validation before opening. Real FIFO subprocess regression has a deadline so a future regression fails rather than hangs. This does not claim race-proof history against hostile same-UID writers. |
| Validator maintained an explicit list of test files | Replaced with discovery of all `tests/`; required mode rejects every skip and absence of passing boundary tests. Existing subprocess regressions exercise the rejection gate with/without terminal output. |
| Fixture docstring described /usr/local as exposed | Corrected: it is an outside dummy location that must be absent; the setuid helper uses an explicitly selected temporary workspace. |
| Installed smoke did not include the walkthrough's hard denial | Added actual `sudo id` denial with exit 3 even with --yes, including policy/decision assertions. This runs on the installed wheel, not a mocked backend. |

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
and [tester checklist](TESTER_CHECKLIST.md). Remote CI configuration review is not a CI pass.
