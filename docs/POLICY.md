# Policy v1

Discovery is intentionally simple: built-in trusted defaults, followed by exactly
`WORKSPACE/.safeshell.toml`. There is no ancestor walk, global policy or ambient environment
override. `--policy PATH` selects a replacement file; it receives exactly the same validation
and cannot widen the trusted baseline. Policy is read once into memory and the same object
is used for the launch decision; editing its file after approval cannot change that decision.

```toml
version = 1
preset = "offline"
workspace = "."
network = "off"
environment = []
confirmation = "risk"
audit = "metadata"
hard_denied = ["privilege", "credentials", "containers"]
```

All fields are optional and have the displayed defaults. Unknown fields, incorrect types,
symlink policy files, files over 64 KiB and unsupported values fail validation.

| Key | Supported values / meaning |
| --- | --- |
| version | Integer 1 only |
| preset | offline, development, strict |
| workspace | `.` only; CLI `--workspace` is the sole writable host root |
| network | `off` only; neither domains nor online modes are accepted |
| environment | Subset of LANG, LC_ALL, TZ; values come from the host and are never stored |
| confirmation | risk or always; cannot disable confirmation |
| audit | metadata or redacted; no raw command/output mode |
| hard_denied | Must include privilege, credentials, containers; may additionally deny identified network requests |

All presets enforce the same offline boundary. Offline and development require confirmation
for medium/high risk or uncertain reports. Development is a named equivalent for future
compatibility, not a less restrictive mode. Strict requires confirmation for every execution.
Explicit values that conflict with the strict preset are rejected.

`hard_denied` rejects identified requests; it is not a general syscall capability language.
The previously accepted `filesystem-write` value is now rejected: the implemented backend
always grants a writable workspace, so static detection alone cannot enforce that setting.
Credentials inside the workspace remain accessible even though known credential-request
signals are hard-denied. Runtime filesystem/network/privilege restrictions apply to all code.

Environment additions are limited to non-control locale/timezone values below 256 characters.
PATH, loader options, interpreter startup variables, credentials, SSH agents, proxy and cloud
variables cannot be inherited. `/usr/bin:/bin` is the fixed PATH.

No repository file may silently expand permissions. Adding locale inheritance or changing
metadata-only audit to redacted mode requires review of the file and `--review-policy` on that
invocation (including `policy validate`). That acknowledgment permits only those two bounded
expansions; network, hard-denial and environment-name limits cannot be relaxed. Explicit
`--policy` selection alone does not imply review. Requests beyond the baseline are rejected.
`--yes` approves only a permitted
risk decision. It cannot change a hard denial, unsupported syntax, backend capability, mounts,
network or environment restrictions. Capability names refer to static signals; arbitrary code
can hide intentions, so the runtime boundary is always applied independently of risk scoring.

Workspace paths are resolved, not glob-expanded. Home/root/system selections, credential
directories and nested Linux mounts are refused. Before execution, workspace entries are
checked for hardlinks, sockets, FIFOs and devices. Symlinks remain symlinks inside the new mount
namespace; host paths outside the exposed trees are absent. There is a 200000-entry scan limit.
Concurrent workspace changes remain a race; use a private disposable copy for untrusted repos.

The alpha runtime file set cannot be expanded through a repository policy. Wall-clock and
output limits are CLI `run` options, not policy keys; unsupported CPU/memory/process/disk settings
are rejected as unknown keys. See README for enforced limits and docs/WORKSPACES.md for copying.
