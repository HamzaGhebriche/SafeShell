# Alpha candidate validation — final review 2026-10-31

**Experimental alpha; public GitHub prerelease authorized. No production-readiness claim.**
The target is [HamzaGhebriche/SafeShell](https://github.com/HamzaGhebriche/SafeShell).
Owner/remote are verified. Normal history is preserved; no registry publication is performed.
See [PUBLIC_REVIEW.md](PUBLIC_REVIEW.md), [VirtualBox](VIRTUALBOX.md) and
[friend testing](FRIEND_TESTING.md). The final release body identifies the tagged commit,
successful final workflow and asset checksums. Earlier results below are tied to their
recorded source checkpoints and must not be relabeled as final-tag reruns.

## Public prerelease preparation - actual remote results

Commit **`022f37bfcf674eb5dc437d29f5526e8bb4800943`** on `main`:
[checks 41180095409: SUCCESS](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41180095409).
The receipt was downloaded and checked independently, rather than inferred from
workflow configuration. [Machine-readable evidence](validation-public-ci.json).

| Job | Actual result |
| --- | --- |
| [Native Ubuntu linux-boundary](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41180095409/job/124475556979) | **97 passed, zero failures/errors/skips**, all 23 boundary cases; build, required-backend clean wheel and release-asset checks passed |
| [Portable Ubuntu](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41180095409/job/124475556974) | **74 passed, zero skips**; lint/format/build/clean wheel passed; complete boundary file covered separately by required native job |
| [Portable Windows](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41180095409/job/124475556957) | **73 passed, 24 explicit skips**: 23 unsupported Linux boundary cases + POSIX FIFO; build/clean wheel and refusal passed |
| [Portable macOS](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41180095409/job/124475556998) | **74 passed, 23 explicit Linux boundary skips**; build/clean wheel and refusal passed |

The native receipt confirms backend available, 683 planned/observed runtime files
equal, the exact enforced AppArmor stack, and installed-wheel dummy outside/home/
symlink denial, socket EPERM, environment/privilege checks and delayed-descendant
cleanup. Policy denial=3, protected run=0, timeout=124 and output-limit=125 passed.
The Ubuntu global userns restriction remained enabled. No setup failure or skip
was accepted as enforcement evidence. Portable CI now rejects unexpected skips.

`alpha-distributions` contains the checked wheel, sdist and SHA256SUMS from that
checkout; evidence/artifact hashes and source hashes are in the JSON receipt.
The documentation-only follow-up preserves code/test/workflow hashes. Its final
commit and the release tag must pass CI again; the published prerelease body is
the final tag/SHA/run/asset-hash record. These earlier artifact bytes are not
silently substituted for the final tagged build.

Local public-preparation checks: Ruff 0.17.3 format/lint, build/content checks and
fresh offline wheel workflows passed on Windows/Python 3.14.0. Local pytest:
**72 passed, 25 explicit skips** (23 Linux cases, FIFO and a denied hardlink
fixture). The initial local build failed because the desktop sandbox's default
temp directory was unwritable; rerunning with a workspace-local TMP/TEMP passed.
That local environment issue is separate from the successful native CI build.

VirtualBox fresh-guest UI installation has not been automated or represented as
passed; guide command flows are covered by native Ubuntu and installed-wheel
checks. Earlier native Debian/KVM and WSL results below remain separate checkpoints.

## Earlier private-checkpoint remote CI - 2026-10-31

Candidate commit: **`eb621ed941f36e8d869897e2ca41d20121151776`**, branch
`codex/safeshell-alpha-review`.
[Workflow 41176530291: SUCCESS](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176530291).
These are actual remote results, distinct from the earlier local checkpoints below.
The subsequent documentation-only commit records this successful code/test/workflow checkpoint;
its own push must also pass CI before handoff.

| Remote job | Actual result |
| --- | --- |
| [linux-boundary / Ubuntu 24.04 x86_64](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176530291/job/124465126257) | **95 passed, zero failures/errors/skips**, including all 23 boundary cases; sdist/wheel build and required-backend fresh-wheel workflows passed |
| [portable Ubuntu](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176530291/job/124465126562) | **72 passed, zero skips**; boundary file intentionally covered by complete native job; lint/format/build/clean wheel passed |
| [portable Windows](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176530291/job/124465126346) | **71 passed, 24 explicit skips**: 23 Linux boundary cases + POSIX FIFO; lint/format/build/clean wheel and execution refusal passed |
| [portable macOS arm64](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176530291/job/124465126500) | **72 passed, 23 explicit Linux boundary skips**; lint/format/build/clean wheel and execution refusal passed; no Linux arm64 enforcement claim |

The native host reported kernel `7.0.0-1017-azure`, glibc 2.39, Python 3.11.17,
Bubblewrap 0.9.0, test UID 1001. Uploaded JUnit was independently inspected: all
95 cases present, including 23 boundary cases, with zero failures/errors/skips.
Doctor reported available; observed/planned runtime file sets matched exactly (683).
The observed AppArmor label was `safeshell-bwrap//&safeshell-child (enforce)` and
the workflow asserted the global user-namespace restriction remained 1. This is
**Ubuntu with the documented scoped CI profile**, not stock-Ubuntu out-of-box verification.

The installed wheel reported 0.1.0a1, backend available, policy denial 3, protected
execution 0, output limit 125, timeout 124, and all history/explain/policy workflows
passed. Fresh venv, no system packages, offline install and unrelated cwd were required.
Wheel SHA256: `f3bfc0bd5830bb71bf59de8a1876e44b1e7a9515151ab3bdf2c791f1da45f484`.

[Evidence artifact 13032768164](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176530291/artifacts/13032768164):
`linux-enforcement-evidence`, archive SHA256
`82dc00e9c2fb15432c2dfb48431344a88654bc929825803f3654a71c27fc5c69`.
Artifact retention expires 2027-01-29; compact results, source hashes and per-file
evidence hashes are committed in [validation-remote-ci.json](validation-remote-ci.json).
Raw logs/artifacts remain ignored, separate from application command history.

### Earlier remote failures — preserved, not counted as passes

All attempts used normal commits and retained strict checks. Full SHAs/links are
in the remote JSON receipt. The initial matrix cancelled Windows/macOS on failure;
matrix fail-fast was then disabled so each platform could finish independently.

| Run | Actual failure and resolution |
| --- | --- |
| [41174695711](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41174695711) | Generic Ubuntu AppArmor denied loopback setup (72 passed/23 setup errors); new Ruff defaults found 33 lint issues. Fixed lint findings/pinned version; added scoped CI profile. |
| [41175543723](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41175543723) | Exact guest-label gate rejected retained setup domain before pytest. Windows/macOS had old setuptools incompatible with license metadata; required >=77. |
| [41175911202](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41175911202) | Enforced setup profile lacked lookup permissions; macOS source check compared lexical temp-path aliases; resolved paths while retaining containment assertion. |
| [41176023810](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176023810) | Audit identified Unix datagram socket needed for trusted loopback interface lookup. All portable jobs passed. |
| [41176085007](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176085007) | Root-directory lookup needed an explicit AppArmor rule. All portable jobs passed. |
| [41176180094](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176180094) | NNP rejected replacement profile transition; changed to intersecting stack, retaining NNP. All portable jobs passed. |
| [41176290527](https://github.com/HamzaGhebriche/SafeShell/actions/runs/41176290527) | **93 passed, 2 failed, no skips**: null-descriptor metadata denied and one-second fixture expired during setup. Scoped disconnected-path lookup; timeout cleanup now 5s with 8s delayed write and 8.3s post-exit observation, retaining both assertions. All portable jobs passed. |

No security test became skip/xfail. Backend mounts, seccomp, NNP, network separation
and fail-closed behavior were retained. See [CI_HANDOFF.md](CI_HANDOFF.md) for exact
Ubuntu setup/reproduction and [FINAL_REVIEW.md](FINAL_REVIEW.md) for findings.

## Earlier local validation — separate source checkpoints

The summaries below retain the original source/test/wheel hashes. They predate
remote CI fixes; they are not claimed as final-commit Debian/WSL reruns.

| Environment | Actual result | Scope |
| --- | --- | --- |
| Ubuntu 24.04.1 / WSL2 x86_64 | **95 passed, zero skips** | Kernel 6.18.54.1-microsoft-standard-WSL2, glibc 2.39, Python 3.12.3, bubblewrap 0.9.0; tests as UID 65534 |
| Debian 12 native-kernel KVM guest | **95 passed, zero skips** | Kernel 6.1.0-54-cloud-amd64, glibc 2.36, Python 3.11.2, bubblewrap 0.8.0; tests as UID 1000 |
| Native Ubuntu GitHub CI | See actual remote results above | Separate remote evidence; not part of these historical local receipts |
| Windows | **70 passed, 25 explicit skips** | 23 Linux-only boundary cases, 1 denied hardlink fixture and 1 POSIX FIFO fixture; clean installed wheel refusal/history passed |
| Linux aarch64 / other filesystems | **Unverified** | No broader enforcement claim; macOS portable results are above |

Ruff formatting/lint and alpha wheel/source builds passed. A wheel installed offline into a
fresh WSL venv passed explain/script, policy init/validate, doctor, protected run, history
list/show/delete, output-limit and timeout workflows from an unrelated cwd. The verifier checks
installed version metadata and prevents source imports from shadowing the installed package.
Final rerun results and artifact hashes are recorded in the summaries and local evidence below.

The Debian guest ran its own kernel, not a container/chroot or WSL userspace substitution.
It received no host folder, agent or existing SSH key. The official cloud-image HTTPS SHA512
was checked before boot; a temporary key and source archive were copied in. QEMU and the
overlay were removed afterward. CPU/RAM/disk settings on the test VM are not SafeShell quotas.
No host AppArmor or namespace restriction was disabled.

## Evidence and exact coverage

Local evidence: `validation-results/pytest.xml`, `host.json`, `doctor.json`,
`runtime-manifest.json`, `namespace-inventory.json`, `installed-smoke.json`; Debian equivalents
plus image SHA512/source-archive checksum and boot log under `validation-results/debian-review-final/`.
Compact source/result hashes are in `docs/validation-wsl-summary.json` and
`validation-debian-summary.json`. `dist/SHA256SUMS` identifies candidate distribution bytes.
These are explicit validation artifacts with dummy data, not application command-history logs.

Final review fixed non-regular history record handling, switched CI validation to full test
directory discovery, and verified hard policy denial on the installed wheel. The updated Linux
suites passed 95/0 at their recorded checkpoints; actual native Ubuntu CI is recorded above.
See [final findings](FINAL_REVIEW.md), [the exact CI handoff](CI_HANDOFF.md),
[five-minute walkthrough](DEMO.md) and [tester checklist](TESTER_CHECKLIST.md).

The first reduced-recommendations Debian provisioning attempt omitted libc headers. It failed
before tests; this was fixed by requiring build-essential. A regression now prevents stale
JUnit evidence from silently surviving a failed run. Older VM result directories are historical;
only `debian-review-final` is the final candidate run. The exact candidate wheel SHA256 matches
the clean-install reports on Windows, WSL and Debian. Final sdist documentation/evidence updates
are checked separately against the validated source/test hashes; no bit-for-bit build claim.

| Tested claim | Actual checks / remaining limit |
| --- | --- |
| Workspace access and argv | Host input/output checks, empty/whitespace/metacharacter round-trip; granted files remain destructible |
| Outside data absent | Dummy outside file and SSH/AWS/Kubernetes/Docker/Git home stores, absolute/relative symlink reads/writes, traversal and fixed sensitive-location absence checks; real secrets never read |
| Minimal readonly runtime | Actual runtime file set exactly equals manifest: Ubuntu 683, Debian 677; no broad tree mounts; root/proc/file ro flags; old host-readable /usr/local dummy absent; approved code and proc metadata still readable |
| Offline | Host socket controls succeed; guest IPv4/IPv6/Unix socket creation returns EPERM before connect; no packet-capture/online claim |
| Env/FD isolation | Dummy secrets absent, fixed HOME/PATH, deliberately inheritable secret-file and socket FDs excluded |
| Descendants/privilege | Grandchild inheritance, real host-elevating setuid control that does not elevate in sandbox, no-new-privileges/capabilities and direct syscall denials |
| Cleanup/limits | Normal exit, timeout, raw output cap, slow consumer, SIGINT/SIGTERM and supervisor SIGKILL; delayed descendant writes absent |
| No fallback | Invalid real bwrap setup option, exact Popen spy and absolute host marker; unavailable/exception unit paths |
| Policy/privacy/JSON | Strict values, permission review, noninteractive decisions, redaction, escaping, exit statuses; NTFS ACLs not verified |
| Required gate | Skip rejection with/without terminal plugin and failure for missing passing boundary tests; actual native Ubuntu run passed this gate |

All nine original skips received real Linux coverage: workspace/child, outside/symlink, host
write, sockets, environment/privilege, normal/timeout cleanup, argv layout and real hardlink
rejection. Layout is portable now. Hardlink fixture creation may explicitly skip on restricted
Windows; every skip fails a required Linux run. Runtime files must be root-owned/non-writable
by other users, including parent directories. They are not an immutable runtime image.

## Reproduce

For root-default WSL, first change into your checkout within the Linux distro,
install the listed distro dependencies, then run `python3 tools/validate_linux.py
--as-user nobody` from the root harness. All actual probes/tests run unprivileged.
For new testing, prefer the complete normal-user VirtualBox guide instead of
assuming another developer's Windows checkout path or WSL configuration.

Nonroot disposable Linux host with passwordless sudo:

```sh
sudo apt-get update
sudo apt-get install -y bubblewrap libseccomp2 python3-pytest python3-venv build-essential
python3 tools/validate_linux.py
python3 tools/smoke_installed.py dist/safeshell_cli-0.1.0a1-py3-none-any.whl --require-backend
```

The runner temporarily provisions/removes a harmless root-owned UID-reporting executable and
outside dummy. Only fixture setup uses root. Every actual probe/test is unprivileged.

Native Debian VM on Linux/KVM (WSL host works; the guest has its own kernel):

```sh
sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils openssh-client
python3 tools/debian_vm.py dist/safeshell_cli-0.1.0a1.tar.gz --wheel dist/safeshell_cli-0.1.0a1-py3-none-any.whl --results validation-results/debian-new
```

It checks official HTTPS SHA512SUMS, boots a temporary overlay, installs signed distro packages,
runs zero-skip tests and clean install, retrieves evidence and removes VM/keys. Image cache
remains reusable. Require the same cached base with `--image-sha512` from the recorded image.json.
Package versions may update; evidence records actual versions. Vagrant remains an untested
alternative provider configuration. No container is substituted for this native-kernel test.

Windows checks/build:

```powershell
New-Item -ItemType Directory -Force .build-tmp | Out-Null
$env:TMP = "$PWD\.build-tmp"
$env:TEMP = $env:TMP
python -m ruff format --check .
python -m ruff check .
python -m pytest -ra --basetemp=.test-alpha-final
python -m build --no-isolation
python tools/smoke_installed.py dist/safeshell_cli-0.1.0a1-py3-none-any.whl
```

The native Ubuntu CI gate passed on the recorded commit with the scoped test-host profile.
Use CI_HANDOFF.md for that exact reproduction; the generic Linux commands above do not load
AppArmor policy. Other architectures, concurrent host writers,
FUSE/network/DrvFS workspaces, alternate ABIs, CPU/memory/process/disk containment and independent
security review have no verification claim. See [workspace races](WORKSPACES.md),
[the mount inventory](SANDBOX.md) and [release notes](../RELEASE_NOTES.md).
