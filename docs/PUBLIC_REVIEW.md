# Experimental alpha public-readiness review

The user explicitly authorized public visibility, ordinary commits/pushes and a
GitHub **experimental prerelease** for HamzaGhebriche/SafeShell. No PyPI or other
package-registry publication is part of this release. Existing history is kept.

## History and privacy review

The initial public-readiness scan covered all nine reachable commits and **87
unique blobs / 423258 bytes** through
`bff190d92786eeec0381a2a00fbf3d4416ff4e22`. It checked reachable blobs and commit
messages for known credential/key/token patterns and reviewed tracked filenames
for local state, history, build output and temporary artifacts. No credential or
private runtime artifact was identified. This is a bounded automated/manual
review, not a claim that secret detection is infallible. Normal author attribution
and historical nonsecret environment/checkpoint metadata remain in Git history.

`.build-tmp/github_ops.py` was inspected specifically. It loads a Git credential
into process memory, contains no embedded token and was **never tracked in any
reachable commit**. `.build-tmp/` was already ignored; extra root-helper, venv,
release-asset and local environment ignore rules were added. No temporary helper,
token, raw application audit directory or local build artifact is included in
the public source or built distribution. A file deletion alone would not remediate
a credential in history; discovery of one would block publication pending rotation
and a separately reviewed remediation. No rewrite was needed for this review.

The final staged tree/reachable history is checked again before visibility changes.
Review receipts and downloaded build artifacts stay ignored locally; committed
validation JSONs contain explicit dummy-test results/source hashes, not application
command-history records. Public instructions use repository-relative links and
portable guest paths instead of a developer's local Windows checkout.

## Reliability changes

- Native Linux keeps its complete-suite zero-skip/backend gate. Portable CI now
  fails unexpected skips, accepting only explicit unsupported-platform cases.
  Subprocess regressions verify rejection with/without terminal output.
- Build metadata includes the README/repository links. Distribution checks compare
  source bytes, require the profile/guides and reject private/generated paths.
  Native CI retains the exact built wheel/sdist/checksums as an artifact.
- Installed-wheel smoke now runs the supplied dummy boundary fixture and delayed
  descendant cleanup. It requires outside/home/symlink denial, socket EPERM,
  environment exclusion and privilege controls rather than only predicted risk.
- The public README, full VirtualBox guide, five-minute friend guide, security
  channel, contribution guide and issue templates reflect actual CLI behavior.

## Evidence and limitations

[VALIDATION.md](VALIDATION.md) records real CI results and source checkpoints.
The prerelease body records the final tested tag SHA, final workflow URL and exact
asset SHA256 values. Builds/clean installs and native boundary CI must pass before
the visibility change or prerelease publication. No check is bypassed to publish.

VirtualBox is available on the development host, but its manual fresh-guest UI
installation sequence is not an automated validation claim. The guide's Linux
command flows are exercised by native Ubuntu CI and installed-wheel checks.
Earlier Debian/KVM and WSL receipts remain historical checkpoints, separately labeled.

**Experimental-alpha testing only. No independent security audit.** Writable
workspace files remain readable, writable and destructible; use disposable copies.
Concurrent host writers, runtime-update races, kernel vulnerabilities and untrusted
generated outputs remain risks. Runtime code/proc metadata remain readable.
CPU, memory, process-count and disk quotas are absent. Windows/macOS protected
execution is refused; NTFS history ACLs, other Linux architectures/filesystems and
alternate ABIs have no verification claim. No production-readiness claim is made.
