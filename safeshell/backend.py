"""Linux bubblewrap launcher. There is intentionally no host fallback."""

import ctypes
import errno
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from . import runtime
from .policy import Policy, environment


@dataclass
class Capability:
    available: bool
    backend: str
    reason: str


class ExitStatus(int):
    def __new__(cls, value, termination_reason="launcher-exit"):
        result = super().__new__(cls, value)
        result.termination_reason = termination_reason
        return result


RESTRICTIONS = {
    "filesystem": "Workspace writable; individually mounted alpha runtime code read-only; no host /usr/local/share/home; ephemeral home/tmp",
    "network": "Network namespace plus seccomp denial of socket operations and io_uring",
    "environment": "Fresh fixed environment plus explicitly allowlisted locale variables",
    "privilege": "User/PID/IPC/UTS namespaces, no new privileges, all capabilities dropped",
    "lifecycle": "PID namespace and die-with-parent; descendants end with sandbox init",
    "observed_events": "Exit status only; no file-change or network-event monitoring",
}


def workspace_path(value: str) -> Path:
    root = Path(value).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Workspace must be a directory")
    if any(
        part.lower() in {".ssh", ".aws", ".kube", ".docker", ".gnupg", ".config"}
        for part in root.parts
    ):
        raise ValueError("Credential/configuration directories cannot be selected as workspaces")
    home = Path.home().resolve()
    forbidden = [Path(root.anchor), home]
    if sys.platform == "linux":
        forbidden += [
            Path(x)
            for x in (
                "/etc",
                "/usr",
                "/var",
                "/tmp",
                "/home",
                "/root",
                "/proc",
                "/sys",
                "/dev",
                "/run",
                "/opt",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
            )
        ]
    if root in forbidden or root in home.parents:
        raise ValueError("Choose a dedicated project directory, not a home, runtime or system root")
    if sys.platform == "linux":
        for protected in forbidden[2:]:
            if (
                protected not in (Path("/tmp"), Path("/home"), Path("/opt"), Path("/var"))
                and protected in root.parents
            ):
                raise ValueError("Workspace cannot be inside protected system resources")
        # A recursive bind can carry unrelated mounted filesystems into the sandbox.
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            target = Path(
                line.split()[4]
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\")
            )
            if target != root and root in target.parents:
                raise ValueError("Nested workspace mounts are unsupported")
    return root


def check_workspace_contents(root: Path) -> None:
    count = 0

    def scan_error(error):
        raise ValueError("Cannot inspect every workspace directory") from error

    for directory, folders, files in os.walk(root, followlinks=False, onerror=scan_error):
        for name in folders + files:
            count += 1
            if count > 200000:
                raise ValueError("Workspace exceeds 200000 entries; select a smaller project")
            info = (Path(directory) / name).lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                raise ValueError("Workspace contains hardlinks; use an independent project copy")
            if not (
                stat.S_ISREG(info.st_mode)
                or stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
            ):
                raise ValueError(
                    "Workspace contains sockets, FIFOs or devices; use a plain project copy"
                )


@contextmanager
def seccomp_file():
    """Export libseccomp's architecture-correct BPF, inherited only by bwrap."""
    # find_library may spawn ldconfig/compiler helpers on the host. Load the
    # established Linux SONAME directly so preparing a filter cannot do that.
    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError as exc:
        raise RuntimeError("libseccomp is required; install libseccomp2") from exc
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not ctx:
        raise RuntimeError("Cannot create seccomp context")
    try:
        with tempfile.TemporaryFile() as stream:
            names = (
                "socket",
                "socketpair",
                "connect",
                "bind",
                "listen",
                "accept",
                "accept4",
                "sendto",
                "sendmsg",
                "sendmmsg",
                "recvmsg",
                "recvmmsg",
                "socketcall",
                "io_uring_setup",
                "ptrace",
                "bpf",
                "mount",
                "umount2",
                "pivot_root",
                "setns",
                "unshare",
                "keyctl",
                "add_key",
                "request_key",
                "fsopen",
                "fsconfig",
                "fsmount",
                "fspick",
                "open_tree",
                "move_mount",
                "mount_setattr",
                "pidfd_getfd",
                "process_vm_readv",
                "process_vm_writev",
                "perf_event_open",
            )
            for syscall in names:
                number = lib.seccomp_syscall_resolve_name(syscall.encode())
                if number < 0 and syscall in (
                    "socket",
                    "connect",
                    "io_uring_setup",
                    "ptrace",
                    "unshare",
                    "setns",
                ):
                    raise RuntimeError(f"libseccomp cannot resolve mandatory syscall: {syscall}")
                if (
                    number >= 0
                    and lib.seccomp_rule_add(ctx, 0x00050000 | errno.EPERM, number, 0) != 0
                ):
                    raise RuntimeError("Cannot install required seccomp rule")
            if lib.seccomp_export_bpf(ctx, stream.fileno()) != 0:
                raise RuntimeError("Cannot export seccomp filter")
            stream.seek(0)
            yield stream
    finally:
        lib.seccomp_release(ctx)


def launch_args(bwrap: str, workspace: Path, command: list[str], fd: int) -> list[str]:
    args = [
        bwrap,
        "--unshare-all",
        "--unshare-user",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--disable-userns",
        "--clearenv",
    ]
    args += ["--dir", "/usr/bin", "--symlink", "usr/bin", "/bin"]
    for source, target in runtime.profile():
        args += ["--ro-bind", source, target]
    args += [
        "--proc",
        "/proc",
        "--remount-ro",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/home",
        "--dir",
        "/home/sandbox",
        "--bind",
        str(workspace),
        "/workspace",
        "--chdir",
        "/workspace",
        "--seccomp",
        str(fd),
    ]
    for key, value in environment(Policy()).items():
        args += ["--setenv", key, value]
    # Root/ordinary directories become read-only; separate workspace/home/tmp/dev
    # mounts retain their own permissions. This is not a recursive remount.
    args += ["--remount-ro", "/"]
    return args + ["--"] + command


def discover() -> Capability:
    if sys.platform != "linux":
        return Capability(
            False,
            "none",
            "Protected execution requires Linux, bubblewrap and libseccomp; inspection is available.",
        )
    if os.geteuid() == 0:
        return Capability(
            False, "bubblewrap", "Run SafeShell from an unprivileged host account, not root."
        )
    binary = shutil.which("bwrap", path="/usr/bin:/bin")
    if not binary:
        return Capability(
            False, "bubblewrap", "Install bubblewrap and libseccomp2; no command was launched."
        )
    info = Path(binary).stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
    ):
        return Capability(
            False,
            "bubblewrap",
            "Require root-owned, non-setuid, non-group/world-writable bubblewrap.",
        )
    try:
        with (
            tempfile.TemporaryDirectory(prefix="safeshell-probe-") as directory,
            seccomp_file() as rules,
        ):
            result = subprocess.run(
                launch_args(binary, Path(directory), ["/usr/bin/true"], rules.fileno()),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env={},
                close_fds=True,
                pass_fds=(rules.fileno(),),
                timeout=10,
                check=False,
            )
            if result.returncode:
                return Capability(
                    False,
                    "bubblewrap",
                    "Sandbox probe failed. Check unprivileged user namespaces, AppArmor and bubblewrap version. "
                    + result.stderr.decode(errors="replace")[:400],
                )
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return Capability(False, "bubblewrap", str(exc))
    return Capability(
        True,
        "bubblewrap",
        "Sandbox setup smoke probe succeeded (fixed true command). Containment tests are separate; each launch may still fail.",
    )


def run(
    workspace: Path,
    command: list[str],
    policy: Policy,
    output,
    timeout: int,
    max_output_bytes: int = 1048576,
) -> int:
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError("Timeout must be 1..86400 seconds")
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 67108864:
        raise ValueError("Output limit must be 1..67108864 bytes")
    capability = discover()
    if not capability.available:
        raise RuntimeError(capability.reason)
    binary = shutil.which("bwrap", path="/usr/bin:/bin")
    # Resolve once more immediately before binding. A concurrent rename is a documented race.
    if workspace_path(str(workspace)) != workspace:
        raise RuntimeError("Workspace changed before launch")
    check_workspace_contents(workspace)
    with seccomp_file() as rules:
        args = launch_args(binary, workspace, command, rules.fileno())
        end = args.index("--")
        for key, value in environment(policy).items():
            args[end:end] = ["--setenv", key, value]
            end += 3

        class Cancelled(Exception):
            def __init__(self, number):
                self.number = number

        def cancel(number, frame):
            raise Cancelled(number)

        previous = signal.signal(signal.SIGTERM, cancel)
        process = None
        output_bytes = 0
        termination_reason = "launcher-exit"
        timed_out = threading.Event()
        watchdog = None

        class OutputLimit(Exception):
            pass

        def terminate():
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()

        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={},
                close_fds=True,
                pass_fds=(rules.fileno(),),
                start_new_session=True,
            )
            os.set_blocking(process.stdout.fileno(), False)
            deadline = time.monotonic() + timeout

            def expire():
                if process.poll() is None:
                    timed_out.set()
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

            # Command execution must end even if a slow terminal blocks output().
            watchdog = threading.Timer(timeout, expire)
            watchdog.daemon = True
            watchdog.start()
            exited_at = None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    status = process.poll()
                    now = time.monotonic()
                    if status is None and now >= deadline:
                        raise subprocess.TimeoutExpired(args, timeout)
                    if status is not None:
                        exited_at = exited_at or now
                        if not selector.get_map():
                            break
                        if now - exited_at > 2:
                            raise RuntimeError(
                                "Sandbox exited but an output descriptor remained open"
                            )
                    for key, _ in selector.select(0.1):
                        block = os.read(key.fd, 65536)
                        if block:
                            remaining = max_output_bytes - output_bytes
                            if remaining:
                                output(block[:remaining])
                            output_bytes += len(block)
                            if output_bytes > max_output_bytes:
                                raise OutputLimit()
                        else:
                            selector.unregister(key.fileobj)
        except (KeyboardInterrupt, subprocess.TimeoutExpired, Cancelled, OutputLimit) as exc:
            terminate()
            termination_reason = (
                "output-limit"
                if isinstance(exc, OutputLimit)
                else "timeout"
                if isinstance(exc, subprocess.TimeoutExpired)
                else "signal"
            )
            status = (
                125
                if isinstance(exc, OutputLimit)
                else 128 + exc.number
                if isinstance(exc, Cancelled)
                else 130
                if isinstance(exc, KeyboardInterrupt)
                else 124
            )
        finally:
            try:
                if watchdog is not None:
                    watchdog.cancel()
                terminate()
                if process is not None:
                    process.stdout.close()
            finally:
                signal.signal(signal.SIGTERM, previous)
        if timed_out.is_set():
            status, termination_reason = 124, "timeout"
        return ExitStatus(status if status >= 0 else 128 - status, termination_reason)


def describe(capability: Capability) -> dict:
    return {
        **asdict(capability),
        "effective_enforcement": None,
        "probed_restrictions": RESTRICTIONS if capability.available else None,
        "probe_scope": "Sandbox setup only; not evidence of containment test results",
        "configured_restrictions": RESTRICTIONS,
    }
