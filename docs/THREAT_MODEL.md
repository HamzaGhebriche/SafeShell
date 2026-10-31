# Threat model and limitations

SafeShell aims to confine malicious command code and its descendants from a nonprivileged
local developer session. The command, checked-out files, policy file, dependencies, command
output and old history records are untrusted. Inspection does not execute or fetch anything
from the submitted command. A local probe executes only a fixed true command in a sandbox.

Trusted computing base: the host Linux kernel, Python runtime and standard library, this
installation, root-managed bubblewrap, libseccomp, and selected distro runtime files and their package
updates. An administrator or malicious process with the same host UID can compromise the
supervisor or modify its inputs and is outside the boundary. Do not run SafeShell as root.
This implementation is an experimental alpha. The real suite passed on WSL2 and a Debian native-kernel VM
in [validation](VALIDATION.md); deployment hosts still need their own actual boundary test run.

## Filesystem

Only the selected host workspace is writable. Sandbox home/tmp and basic devices are separate.
The assembled root and new proc mount are read-only; proc still exposes global kernel metadata.
Only individual approved runtime code files remain visible; they are readable and could contain
embedded secrets. Whole /usr, /usr/local, /usr/share and /etc trees are not exposed. See the exact
inventory in [SANDBOX.md](SANDBOX.md). Workspace credentials remain accessible even if static findings miss them.
The command can destroy every writable workspace file, including Git data and policy files.
Later host builds or hooks may execute modified artifacts: isolation does not make outputs trusted.

Canonical workspace checks reject obvious dangerous choices. A scan rejects pre-existing
hardlinks and host IPC/device objects; nested mounts are refused. Scan, path binding, executable
lookup, and command inspection are not atomic. A hostile concurrent host writer can replace
directories, add mounts, hardlinks or sockets between checking and launch. A dedicated private
copy with no concurrent host writers is required. Symlinks into exposed runtime directories
can still read those intentionally exposed files. No claim is made about arbitrary FUSE or
network/DrvFS filesystems. Missing /etc, locale data, site packages and non-profile programs may
make commands fail; there is no host fallback or policy option to widen the alpha runtime.

## Networking, privileges and processes

Network namespace isolation is paired with architecture-specific libseccomp filters that deny
socket syscalls (including Unix sockets) and io_uring. This also prevents ordinary localhost
networking and many development servers; no domain allowlist is implemented. The filter uses
libseccomp's architecture validation. Alternate syscall ABIs are not enabled. Filtering is
defense in depth, not protection from kernel vulnerabilities or every possible side channel.
Descriptors other than standard streams and the seccomp filter are closed. No host stdin/TTY,
Docker socket or agent descriptor is passed. Seccomp is consumed by bubblewrap; only pipes
and null input remain as child standard streams. An isolated PID namespace and bubblewrap's
parent-death behavior contain descendants. The process group is killed on timeout/Ctrl+C/SIGTERM.
Normal exit, timeout, both handled signals and abrupt supervisor SIGKILL have real delayed-child
cleanup tests on the recorded host.

No memory, disk, CPU, process-count or file-size quotas are currently enforced. Configurable
wall-clock timeout and raw combined-output caps are enforced, including when rendering blocks.
A fork bomb or disk fill may harm the host before timeout fires. Temporary filesystem
data can consume memory. No VM-strength kernel boundary or complete isolation is claimed.

## Parsing and presentation

The quote-aware lexer and recursive-descent parser support a deliberately small shell grammar:
simple commands, pipelines, &&/||/;, and single-path <, >, >> redirects. Quotes, escapes and
empty arguments are preserved for analysis; execution uses the original shell string.
Assignments, substitutions, multiline scripts, compound statements, functions, background jobs,
descriptor redirects and heredocs are unsupported and produce explicit uncertainty and a launch
denial in shell mode. Dollar/backtick/parenthesis/brace syntax is conservatively unsupported even
inside quotes. argv mode never applies shell syntax; interpreter invocations remain arbitrary code.
Aliases, binary contents, dynamic paths and nested languages are not resolved. Script inspection
supports the same grammar and reports unsupported multiline syntax honestly.

Findings are heuristic estimates. A package/test executable can do anything within the effective
boundary. Executables, dependencies and workspace files can change after inspection. Static
hard-denial rules cannot prove that opaque code will not attempt a denied capability; the
backend supplies the actual restriction. Low risk means only no known risk signals detected.

Terminal controls, CR and bidi formatting are escaped. Child line feeds are preserved; output
is not a terminal emulator, and no interactive child input is supported. Child output can still
be misleading text or hyperlinks printed as text. UTF-8 split across output chunks may display
replacement characters. JSON child output is suppressed, never stored. Human-readable history
is escaped on every rendering, including forged records. History is not cryptographically signed.

## Audit

POSIX history requires an owner-only directory (0700), with 0600 record creation and atomic
replacement. Windows inherits the user's profile ACLs; this MVP does not verify or harden NTFS
ACLs. Use a private directory and metadata-only mode there. Do not place history in the writable
workspace: commands could alter it. Metadata-only still exposes timing, risk and rule identifiers.
Redacted mode deliberately omits all arguments, URLs, paths and script text; executable names
can themselves disclose information. There is no observed file/network monitoring. Exit status
is a launcher result, not evidence of command safety or successful confinement on another host.
Abrupt termination or disk failure may leave an incomplete record. Audit failure before launch
prevents execution; failure after launch cannot undo effects already made in the workspace.
