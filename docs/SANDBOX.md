# Alpha filesystem and syscall inventory

Read-only does not mean confidential. The alpha replaces whole runtime-tree binds with a
fixed code-file inventory. [Validation](VALIDATION.md) records observed results and remaining
coverage gaps; the host kernel, bubblewrap, libseccomp, Python and approved distro runtime code
remain trusted. Runtime files could themselves contain embedded secrets and are readable.

## Every source of visible filesystem data

| Sandbox path | Source / access | Confidentiality scope |
| --- | --- | --- |
| `/workspace` | Selected canonical host project, writable bind | All granted content is readable/destructible. Preflight rejects hardlinks, FIFOs/sockets/devices, nested mounts and unreadable scans; concurrent writers remain a race. |
| `/usr/bin/*` | Individual files from the fixed 22-program list | No host bin-directory bind. `/bin` is a synthetic alias. Includes distro Python, not host virtualenvs/SDKs. |
| Selected library paths | Individual transitive ELF DT_NEEDED files and interpreter plus libseccomp | ELF is read as data; no ldd, compiler or loader helper is executed for discovery. Missing dependencies refuse setup. No general `/lib` or `/usr/lib` tree bind. |
| Selected `/usr/lib/python3.X/*` | Individual `.py`/`.so` files listed by root-managed libpython minimal/stdlib package manifests | No site packages, .pth files, sitecustomize/usercustomize, host caches or general share directories. ELF extension dependencies are also selected. |
| `/proc` | New PID-namespace proc mount, read-only | Dynamic process/kernel interfaces, not a host proc bind. Some global kernel information remains visible; this is not a VM secrecy boundary. |
| `/dev` | Bubblewrap minimal devices and descriptor symlinks | Null/random/etc., not host `/dev`; no real terminal/agent/socket inherited. |
| `/tmp`, `/home/sandbox` | New tmpfs/empty home | Writable ephemeral data; no size quota. |
| `/` and generated parent directories | New assembled read-only root | No general `/etc`, `/var`, `/opt`, `/run`, root home or host `/mnt` tree. Separate writable mounts keep their own permissions. |

Runtime files must resolve within approved system code paths, be root-owned regular files,
and not be group/world writable. The resolver accepts distro little-endian ELF64 x86_64/aarch64;
only x86_64 is tested. It follows fixed system library search paths rather than environment
paths or arbitrary executable RPATHs. Runtime selection is cached within a supervisor process;
root-managed runtime/package updates must not race validation/launch. It is not an immutable image.

`safeshell doctor --json` emits `runtime_manifest.files` (host source and guest target), selected
programs, and inventory digest. `tools/capture_inventory.py` walks the actual guest runtime and
requires exact equality with that file list. It also records root entries, directory/symlink
layout, mountinfo and top-level proc/dev entries. Validation observed **683 files on Ubuntu**
and **677 on Debian**. The live data is in `validation-results/runtime-manifest.json` and
`namespace-inventory.json` (and the Debian equivalents).

There is no finite immutable enumeration of future writable workspace/tmp contents or dynamic
proc descriptors. The inventory identifies these dynamic sources explicitly instead of claiming
their contents are fixed. Tests prove dummy host home credentials and an outside file cannot be
read, and check that host `/usr/local`, `/usr/share`, `/etc/passwd`, `/etc/shadow`, `/var`, `/opt`,
`/run`, `/root`, and `/mnt/c` are absent without reading real host secrets. A root-created dummy
under previously exposed `/usr/local` is host-readable but absent in the guest. Known paths
inside exposed runtime code or a workspace are deliberately readable. Symlinks to exposed
runtime files may work; symlinks cannot reveal an otherwise unmounted host path.

## Privileges, environment and processes

Bubblewrap constructs the mount namespace. `--unshare-all` plus mandatory `--unshare-user`
requests user/PID/IPC/network/UTS separation; cgroup separation is opportunistic, not a quota.
`--disable-userns`, capability drops and no-new-privileges prevent supported elevation paths.
The actual root-owned setuid helper is now provided only through its explicitly selected
temporary workspace, not an exception to the runtime allowlist. Tests include its host
elevation control and guest non-elevation, plus failed setuid(0)/unshare and status checks.

Launch starts with empty environment, fixed PATH/HOME/TMPDIR/locale/Git/Python startup controls,
and only reviewed locale inheritance. stdin is null; stdout/stderr are bounded pipes.
`close_fds=True` passes only the filter descriptor to bubblewrap, which consumes it before exec.
Actual tests inject inheritable dummy-secret and socket descriptors. A new session avoids the
host TTY. PID-namespace lifecycle, die-with-parent, and supervisor group termination are tested
for normal exit, timeout, SIGINT/SIGTERM and supervisor SIGKILL.

Wall time and raw combined output have configurable caps; see README. A watchdog ends execution
even if the output consumer stalls. CPU, memory, disk and process counts have **no SafeShell
quota**. Kernel vulnerabilities, fork bombs and resource exhaustion remain possible. Killing
the command does not undo workspace writes or certify resulting artifacts.

## Seccomp

Native libseccomp BPF defaults to ALLOW with explicit EPERM denials. It is a denylist, not an
application syscall allowlist. `libseccomp.so.2` loads directly, without helper subprocesses.
Mandatory syscall resolution, rule insertion or BPF export failures abort launch.

Denied groups: socket creation/pairs and connect/bind/listen/accept/message operations (including
legacy socketcall when native); io_uring_setup; mount/umount/pivot_root and new mount APIs;
unshare/setns; ptrace/process_vm operations/pidfd_getfd; perf_event_open/bpf; keyring operations.
Other than mandatory names, native syscalls unavailable to libseccomp are omitted. Alternate
ABIs are not enabled and have no test claim. Namespace/capability controls supply additional
restrictions. Direct selected syscall tests and IPv4/IPv6/Unix socket creation return EPERM
before connection. No real remote service or packet capture is required or claimed.

See [bubblewrap options](https://github.com/containers/bubblewrap/blob/main/bwrap.xml) and
[the backend source](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c). There is
no host command fallback, network-enabled policy, custom kernel boundary, or extra backend.

## Native Ubuntu CI host policy

Native GitHub Ubuntu uses an application-scoped AppArmor setup profile and an
enforced stacked guest profile, retaining the global user-namespace restriction.
Actual failed CI runs exposed this prerequisite; earlier local WSL had not
exercised it. AppArmor permits reachable files and adds capability/user-namespace
denials. Minimal Bubblewrap mounts and seccomp remain mandatory. This policy is
not another backend or a claim of stock-Ubuntu out-of-box execution. See
[the exact scoped policy, assertions and commands](CI_HANDOFF.md).
