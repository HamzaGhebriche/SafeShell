"""Real boundary tests. Every negative assertion has a working host/guest control."""

import json
import os
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from safeshell import backend, policy

pytestmark = pytest.mark.usefixtures("enforcement")
PYTHON = "/usr/bin/python3"


def run(root, command, timeout=10):
    chunks = []
    status = backend.run(root, command, policy.Policy(), chunks.append, timeout)
    return status, b"".join(chunks).decode(errors="replace")


def python(root, source, *arguments, timeout=10):
    status, output = run(root, [PYTHON, "-c", source, *arguments], timeout)
    assert status == 0, (status, output)
    return output


def test_workspace_read_write_and_argv(tmp_path):
    (tmp_path / "input").write_text("dummy input")
    args = ["a b", "|", "", "$(id)", "--flag"]
    output = python(
        tmp_path,
        "import pathlib,sys,json; assert pathlib.Path('input').read_text()=='dummy input'; pathlib.Path('output').write_text('dummy output'); print(json.dumps(sys.argv[1:]))",
        *args,
    )
    assert json.loads(output) == args
    assert (tmp_path / "output").read_text() == "dummy output"


DENIED_PATHS = """
import errno,json,pathlib,sys
for name in json.loads(sys.argv[1]):
    try: pathlib.Path(name).read_bytes()
    except OSError as e: assert e.errno == errno.ENOENT, (name,e)
    else: raise AssertionError('outside file readable: '+name)
print('absent')
"""


def test_outside_files_and_dummy_home_credentials(tmp_path, monkeypatch):
    workspace = tmp_path / "project"
    workspace.mkdir()
    home = tmp_path / "dummy-home"
    files = [
        ".ssh/id_rsa",
        ".aws/credentials",
        ".kube/config",
        ".docker/config.json",
        ".git-credentials",
    ]
    for name in files:
        path = home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("DUMMY-NOT-A-REAL-SECRET")
        assert path.read_text() == "DUMMY-NOT-A-REAL-SECRET"
    outside = tmp_path / "outside"
    outside.write_text("outside dummy")
    monkeypatch.setenv("HOME", str(home))
    paths = [str(outside), *[str(home / n) for n in files], *["/home/sandbox/" + n for n in files]]
    assert python(workspace, DENIED_PATHS, json.dumps(paths)).strip() == "absent"


def test_symlink_and_traversal_cannot_reach_unexposed_files(tmp_path):
    workspace = tmp_path / "project"
    workspace.mkdir()
    dummy = tmp_path / "outside"
    dummy.write_text("unchanged dummy")
    (workspace / "absolute").symlink_to(dummy)
    (workspace / "relative").symlink_to("../outside")
    (workspace / "runtime").symlink_to("/usr/bin/true")
    paths = ["/workspace/absolute", "/workspace/relative", "/workspace/../outside", str(dummy)]
    python(workspace, DENIED_PATHS, json.dumps(paths))
    status, _ = run(workspace, ["/bin/sh", "-c", "printf changed > absolute"])
    assert status != 0 and dummy.read_text() == "unchanged dummy"
    # Symlinks to explicitly exposed runtime resources are intentionally allowed.
    assert run(workspace, ["/workspace/runtime"])[0] == 0


def test_runtime_and_proc_mounts_read_only(tmp_path):
    fixture = os.environ.get("SAFESHELL_RUNTIME_DUMMY")
    assert fixture, "Use tools/validate_linux.py for the host-writable runtime fixture"
    Path(fixture).write_text("DUMMY-RUNTIME-UNCHANGED")
    python(
        tmp_path,
        """
import errno,os,pathlib,sys
assert not pathlib.Path(sys.argv[1]).exists(), 'Host /usr/local data must not be mounted'
mounts=pathlib.Path('/proc/self/mountinfo').read_text().splitlines()
for target in ('/proc','/','/usr/bin/true'):
    assert any(line.split()[4]==target and 'ro' in line.split()[5].split(',') for line in mounts)
""",
        fixture,
    )
    assert Path(fixture).read_text() == "DUMMY-RUNTIME-UNCHANGED"
    python(
        tmp_path,
        """
import errno,os,pathlib
for path in ['/usr/safeshell-write-test','/usr/bin/true','/proc/sys/kernel/hostname']:
    try: fd=os.open(path,os.O_WRONLY|os.O_CREAT,0o600)
    except OSError as e: assert e.errno in (errno.EROFS,errno.EACCES,errno.EPERM), (path,e)
    else: os.close(fd); raise AssertionError('write unexpectedly allowed: '+path)
pathlib.Path('/tmp/ephemeral').write_text('ok')
pathlib.Path('/home/sandbox/ephemeral').write_text('ok')
""",
    )


@pytest.mark.parametrize(
    "family,address",
    [
        ("AF_INET", ["192.0.2.1", 443]),
        ("AF_INET6", ["2001:db8::1", 443]),
        ("AF_UNIX", "/run/dummy.sock"),
    ],
)
def test_offline_socket_creation_denied(tmp_path, family, address):
    with socket.socket(getattr(socket, family)):
        pass  # Host positive control; no connection or packets.
    # No packets are sent: socket creation must fail with EPERM before connect.
    output = python(
        tmp_path,
        """
import errno,json,socket,sys
try: s=socket.socket(getattr(socket,sys.argv[1]))
except OSError as e: assert e.errno==errno.EPERM; print('socket denied before connect')
else:
    s.close()
    raise AssertionError('socket unexpectedly allowed')
""",
        family,
        json.dumps(address),
    )
    assert output.strip() == "socket denied before connect"


def test_sensitive_environment_and_inheritable_descriptors_excluded(tmp_path, monkeypatch):
    import fcntl

    workspace = tmp_path / "project"
    workspace.mkdir()
    dummy = tmp_path / "dummy-secret"
    dummy.write_text("DUMMY-FD-SECRET")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "DUMMY-ENV-SECRET")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/dummy-agent")
    with dummy.open("rb") as stream, socket.socketpair()[0] as channel:
        fd = fcntl.fcntl(stream.fileno(), fcntl.F_DUPFD, 128)
        os.set_inheritable(fd, True)
        os.set_inheritable(channel.fileno(), True)
        identities = [(os.fstat(n).st_dev, os.fstat(n).st_ino) for n in (fd, channel.fileno())]
        try:
            python(
                workspace,
                """
import errno,json,os,sys
assert 'AWS_SECRET_ACCESS_KEY' not in os.environ
assert 'SSH_AUTH_SOCK' not in os.environ
assert os.environ['HOME']=='/home/sandbox'
assert os.environ['PATH']=='/usr/bin:/bin'
assert os.read(0,1)==b''
denied={tuple(x) for x in json.loads(sys.argv[1])}
for name in os.listdir('/proc/self/fd'):
    try: info=os.fstat(int(name))
    except OSError as e: assert e.errno==errno.EBADF; continue
    assert (info.st_dev,info.st_ino) not in denied
""",
                json.dumps(identities),
            )
        finally:
            os.close(fd)


def test_child_inherits_filesystem_network_and_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("DUMMY_SECRET", "child-must-not-inherit")
    workspace = tmp_path / "project"
    workspace.mkdir()
    dummy = tmp_path / "outside"
    dummy.write_text("DUMMY")
    child = """
import errno,os,pathlib,socket,sys
assert 'DUMMY_SECRET' not in os.environ
assert not pathlib.Path(sys.argv[1]).exists()
try: socket.socket()
except OSError as e: assert e.errno==errno.EPERM
else: raise AssertionError('socket allowed in descendant')
pathlib.Path('child-result').write_text('inherited')
"""
    python(
        workspace,
        "import subprocess,sys; subprocess.run([sys.executable,'-c',sys.argv[1],sys.argv[2]],check=True)",
        child,
        str(dummy),
    )
    assert (workspace / "child-result").read_text() == "inherited"


def test_privilege_escalation_and_namespace_changes_denied(tmp_path):
    python(
        tmp_path,
        """
import ctypes,errno,os,pathlib
status=pathlib.Path('/proc/self/status').read_text()
assert 'NoNewPrivs:\\t1' in status
assert 'CapEff:\\t0000000000000000' in status
assert os.geteuid()!=0
try: os.setuid(0)
except OSError as e: assert e.errno in (errno.EPERM,errno.EINVAL)
else: raise AssertionError('setuid(0) succeeded')
assert os.geteuid()!=0
lib=ctypes.CDLL(None,use_errno=True)
assert lib.unshare(0x10000000)==-1 and ctypes.get_errno()==errno.EPERM
""",
    )


def test_setuid_executable_cannot_gain_privileges(tmp_path):
    fixture = os.environ.get("SAFESHELL_SETUID_FIXTURE")
    if not fixture:
        pytest.fail(
            "Use python tools/validate_linux.py to provision the temporary setuid test helper"
        )
    info = Path(fixture).stat()
    assert info.st_uid == 0 and info.st_mode & stat.S_ISUID
    host = subprocess.check_output([fixture], text=True).strip().split()
    assert int(host[0]) == os.getuid() and int(host[1]) == 0, "Host fixture must actually elevate"
    status, output = run(Path(fixture).parent, ["/workspace/euid"])
    assert status == 0 and [int(x) for x in output.split()] == [os.getuid(), os.getuid()]


def test_sensitive_syscalls_return_eperm(tmp_path):
    python(
        tmp_path,
        """
import ctypes,errno
seccomp=ctypes.CDLL('libseccomp.so.2')
seccomp.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]
seccomp.seccomp_syscall_resolve_name.restype=ctypes.c_int
libc=ctypes.CDLL(None,use_errno=True)
libc.syscall.restype=ctypes.c_long
for name in (b'connect',b'io_uring_setup',b'unshare',b'ptrace',b'bpf',b'fsopen',b'pidfd_getfd'):
    number=seccomp.seccomp_syscall_resolve_name(name)
    assert number>=0, name
    ctypes.set_errno(0)
    result=libc.syscall(number,0,0,0,0,0,0)
    assert result==-1 and ctypes.get_errno()==errno.EPERM, (name,result,ctypes.get_errno())
""",
    )


def test_descendants_die_on_normal_exit(tmp_path):
    status, _ = run(
        tmp_path, ["/bin/sh", "-c", "(sleep 1; echo escaped > late) & echo ready > ready; exit 0"]
    )
    assert status == 0 and (tmp_path / "ready").exists()
    time.sleep(1.3)
    assert not (tmp_path / "late").exists()


def test_timeout_cleanup(tmp_path):
    # The timeout includes namespace setup. Leave startup headroom on hosted
    # AppArmor runners, then wait beyond the descendant's entire write delay.
    # Keep both the ready control and the no-late-write assertion mandatory.
    status, _ = run(
        tmp_path,
        ["/bin/sh", "-c", "echo ready > ready; (sleep 8; echo escaped > late) & wait"],
        timeout=5,
    )
    assert status == 124 and (tmp_path / "ready").exists()
    time.sleep(8.3)
    assert not (tmp_path / "late").exists()


@pytest.mark.parametrize("number", [signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGKILL", 9)])
def test_signal_cleanup(tmp_path, number):
    workspace = tmp_path / "project"
    workspace.mkdir()
    env = dict(os.environ, SAFESHELL_STATE_DIR=str(tmp_path / "history"))
    command = [
        sys.executable,
        "-m",
        "safeshell",
        "run",
        "--json",
        "--yes",
        "--workspace",
        str(workspace),
        "--",
        "/bin/sh",
        "-c",
        "echo ready > ready; (sleep 2; echo escaped > late) & wait",
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        deadline = time.monotonic() + 15
        while not (workspace / "ready").exists():
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline, "sandbox never started"
            time.sleep(0.05)
        process.send_signal(number)
        output, errors = process.communicate(timeout=10)
        if number == signal.SIGKILL:
            assert process.returncode == -number
            records = list((tmp_path / "history").glob("*.json"))
            assert len(records) == 1
            assert json.loads(records[0].read_text())["status"] == "launching"
        else:
            assert process.returncode == 128 + number, errors
            assert json.loads(output)["session"]["exit_code"] == 128 + number
        time.sleep(2.2)
        assert not (workspace / "late").exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def test_real_setup_failure_never_executes_on_host(tmp_path):
    original = backend.launch_args
    popen = subprocess.Popen
    marker = tmp_path / "host-marker"

    def broken(binary, workspace, command, fd):
        args = original(binary, workspace, command, fd)
        args[1:1] = ["--safeshell-invalid-setup-option"]
        return args

    # Only bypass the already-passed smoke probe so the real launch fails after approval.
    # Actual bwrap and Popen remain real. This is fault injection, not an isolation proof.
    with (
        patch.object(
            backend,
            "discover",
            return_value=backend.Capability(True, "bubblewrap", "fault injection"),
        ),
        patch.object(backend, "launch_args", side_effect=broken),
        patch.object(backend.subprocess, "Popen", wraps=popen) as launches,
    ):
        status, output = run(
            tmp_path,
            [
                PYTHON,
                "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('HOST-FALLBACK')",
                str(marker),
            ],
        )
    assert launches.call_count == 1
    assert Path(launches.call_args.args[0][0]).name == "bwrap"
    assert status != 0 and "--safeshell-invalid-setup-option" in output
    assert not marker.exists()


def test_workspace_special_files_and_hardlinks_rejected(tmp_path):
    dummy = tmp_path / "dummy"
    dummy.write_text("dummy")
    alias = tmp_path / "alias"
    alias.hardlink_to(dummy)
    with pytest.raises(ValueError, match="hardlinks"):
        backend.check_workspace_contents(tmp_path)
    alias.unlink()
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(ValueError, match="FIFOs"):
        backend.check_workspace_contents(tmp_path)


def test_workspace_credentials_remain_within_the_grant(tmp_path):
    dummy = tmp_path / ".aws" / "credentials"
    dummy.parent.mkdir()
    dummy.write_text("DUMMY-WORKSPACE-CREDENTIAL")
    assert (
        python(
            tmp_path, "import pathlib; print(pathlib.Path('.aws/credentials').read_text())"
        ).strip()
        == "DUMMY-WORKSPACE-CREDENTIAL"
    )


def test_no_broad_runtime_or_sensitive_host_mounts(tmp_path):
    fixture = os.environ["SAFESHELL_RUNTIME_DUMMY"]
    assert Path(fixture).read_text() == "DUMMY-RUNTIME-UNCHANGED"
    source = """
import os,pathlib,sys
for path in (sys.argv[1],'/usr/local','/usr/share','/etc/shadow','/etc/passwd','/etc/alternatives','/var','/opt','/run','/root','/home/root','/mnt/c'):
    assert not pathlib.Path(path).exists(), path
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
    target=line.split()[4]
    assert target not in ('/usr','/usr/bin','/usr/lib','/lib','/lib64'), target
"""
    python(tmp_path, source, fixture)


def test_output_limit_and_descendant_cleanup(tmp_path):
    blocks = []
    status = backend.run(
        tmp_path,
        [
            "/bin/sh",
            "-c",
            "(sleep 1; echo escaped > late) & /usr/bin/python3 -c 'import os; os.write(1,b\"x\"*10000)' ; wait",
        ],
        policy.Policy(),
        blocks.append,
        5,
        512,
    )
    assert status == 125 and status.termination_reason == "output-limit"
    assert len(b"".join(blocks)) == 512
    time.sleep(1.2)
    assert not (tmp_path / "late").exists()


def test_timeout_even_with_slow_output_consumer(tmp_path):
    def slow(block):
        time.sleep(1.6)

    status = backend.run(
        tmp_path,
        ["/bin/sh", "-c", "echo ready; sleep 1.3; echo escaped > late"],
        policy.Policy(),
        slow,
        1,
    )
    assert status == 124 and status.termination_reason == "timeout"
    assert not (tmp_path / "late").exists()
