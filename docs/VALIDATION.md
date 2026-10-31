# Alpha candidate validation — final review 2026-10-31

**Reviewable, not ready for publication:** native Ubuntu CI remains unverified. The user has
now authorized a normal private-repository commit/push. The dedicated private target is
https://github.com/HamzaGhebriche/SafeShell; its owner and privacy were verified. Initial remote
CI is pending. Packages and releases remain unpublished. Earlier results below are local
WSL/Debian/Windows validation, not remote CI.

| Environment | Actual result | Scope |
| --- | --- | --- |
| Ubuntu 24.04.1 / WSL2 x86_64 | **95 passed, zero skips** | Kernel 6.18.54.1-microsoft-standard-WSL2, glibc 2.39, Python 3.12.3, bubblewrap 0.9.0; tests as UID 65534 |
| Debian 12 native-kernel KVM guest | **95 passed, zero skips** | Kernel 6.1.0-54-cloud-amd64, glibc 2.36, Python 3.11.2, bubblewrap 0.8.0; tests as UID 1000 |
| Native Ubuntu GitHub CI | **Unverified** | No suitable published repository/commit for this standalone folder; detected Git remote belongs to unrelated parent repository; pushes prohibited |
| Windows | **70 passed, 25 explicit skips** | 23 Linux-only boundary cases, 1 denied hardlink fixture and 1 POSIX FIFO fixture; clean installed wheel refusal/history passed |
| macOS / aarch64 / other filesystems | **Unverified** | No broader enforcement claim |

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
suites pass 95/0; native Ubuntu CI is still configuration-only review, not an actual run.
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
| Required gate | Skip rejection with/without terminal plugin and failure for missing passing boundary tests; native Ubuntu CI still needs a run |

All nine original skips received real Linux coverage: workspace/child, outside/symlink, host
write, sockets, environment/privilege, normal/timeout cleanup, argv layout and real hardlink
rejection. Layout is portable now. Hardlink fixture creation may explicitly skip on restricted
Windows; every skip fails a required Linux run. Runtime files must be root-owned/non-writable
by other users, including parent directories. They are not an immutable runtime image.

## Reproduce

This root-default WSL installation, from PowerShell in the checkout:

```powershell
wsl -d Ubuntu -- /bin/sh -c 'apt-get update && apt-get install -y bubblewrap libseccomp2 python3-pytest python3-venv build-essential'
wsl -d Ubuntu --cd /mnt/c/Users/kali/SafeShell -- python3 tools/validate_linux.py --as-user nobody
wsl -d Ubuntu --cd /mnt/c/Users/kali/SafeShell -- runuser -u nobody -- python3 tools/smoke_installed.py dist/safeshell_cli-0.1.0a1-py3-none-any.whl --require-backend
```

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

Native Ubuntu CI is the remaining release gate. Other architectures, concurrent host writers,
FUSE/network/DrvFS workspaces, alternate ABIs, CPU/memory/process/disk containment and independent
security review have no verification claim. See [workspace races](WORKSPACES.md),
[the mount inventory](SANDBOX.md) and [release notes](../RELEASE_NOTES.md).
