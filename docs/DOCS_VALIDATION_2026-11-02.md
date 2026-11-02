# Documentation validation - 2026-11-02 (Europe/Paris)

Scope: README, VirtualBox and friend-guide instructions for the **existing released
0.1.0a1 wheel**, not an application change or another release. Origin and public
repository metadata were verified as `HamzaGhebriche/SafeShell`, default branch
`main`. No revised README attachment was supplied with this request.

## Actually executed

The guide shell blocks were extracted from the edited Markdown. All **31 fenced
shell blocks** passed `bash -n`; the generated execution harness also passed.
Relative file links and heading anchors were checked. CLI flags were reviewed
against the released interface and exercised in the workflows below.

In existing Ubuntu/WSL2, kernel `6.18.54.1-microsoft-standard-WSL2`, an isolated
temporary harness ran the non-administrative recipes as **UID 65534**, using an
existing unprivileged fixture identity, a temporary HOME, fresh venv and disposable
workspaces. It did not create a login account or modify host policy. The published
wheel/source/checksum files were downloaded from their documented URLs; both
distribution checksums passed. The wheel was installed with `--no-index --no-deps`
from outside the source checkout. Version: **0.1.0a1**.

| Released CLI workflow | Actual result |
| --- | --- |
| Doctor JSON redirected to file; three-field summary | Available True, successful fixed setup probe, exit 0; not a containment proof |
| New offline policy init/validate | Passed, network off |
| README and friend first execution | Exit **0**, host file visibly contained **SAFESHELL_OK** |
| `sudo id` policy denial, including `--yes` | Exit **3** |
| Direct `curl ... \| bash` inspection | Explain **0**, SS010 present |
| `curl ... \| sudo bash` inspection | Explain **0**, SS010 absent, privilege denial present; actual run also denied with **3** |
| Supplied dummy fixture | **6/6 passed**: outside/home/symlink denial, socket EPERM, environment exclusion and privilege controls |
| Timeout and delayed descendant | Exit **124**, readiness present, no delayed write after the observation wait |
| Combined-output limit | Exit **125** |
| History list/show/delete | Passed; deletion checked against the resulting session list |

The actual boundary label was **`"kernel\u0000"`**. This does **not** verify
`safeshell-bwrap//&safeshell-child (enforce)`. Six successful dummy checks and a
successful doctor must not be relabeled as verification of that AppArmor stack.
The guide keeps the VM-specific exact assertion; it was syntax-checked, not run
or relaxed on WSL. No new VirtualBox boot, installation or enforcement test occurred.

The user separately reported a successful regular-user Ubuntu 24.04/WSL2 manual
wheel workflow with the same visible execution, denial, six checks, limits and
history outcomes. That user report and this unprivileged automated recipe run are
distinct from the earlier native Ubuntu CI / Debian VM evidence in
[VALIDATION.md](VALIDATION.md).

## Reviewed or syntax-checked, not executed in this pass

- Root-to-existing-login-user and create-only-if-needed account recovery branches.
- Administrative apt installation, VirtualBox installation/network settings,
  scoped AppArmor loading/removal and the optional full enforcement harness.
- Native Windows/macOS refusal, which retains earlier CI evidence. WSL is Linux
  and cannot substitute for those native-platform checks.

The current environment already had prerequisites. Dummy workspace fixtures were
removed afterward. Raw test logs remain ignored locally; no application audit
records or temporary harness scripts were added to Git.

## Release preservation and limits

Release tag `v0.1.0-alpha` continues to identify
`94da62306ae9b608f27ab6e8e130363904988c86`. The existing release files are unchanged:

| Asset | SHA256 |
| --- | --- |
| `safeshell_cli-0.1.0a1-py3-none-any.whl` | `e7b3c080bf0ce5fe3141b06dcfb4c60540d9c52fb414a414037119c6082f0269` |
| `safeshell_cli-0.1.0a1.tar.gz` | `d4a6ec7cb564f5dd07c04ffabbdb9ce7085a32bc3d3cebda6ad1831f7f454f01` |
| `SHA256SUMS` | `aec104d97a4b7106e5fc55489ab7a654199fbdccf568395b86f499faf52ab7f7` |

No application code, tag, release metadata or release asset is changed by this
documentation task. No package/new release is published. The SS010 inconsistency
is documented rather than fixed silently; it is not a demonstrated sandbox bypass.
Workspace exposure, concurrent-writer races, absent CPU/memory/process/disk quotas
and lack of an independent security audit remain. New documentation-push CI, if
reported, is separate from the released-wheel recipe validation above.
