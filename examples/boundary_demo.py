"""Dummy-only installed-CLI demonstration; run inside a disposable workspace."""

import errno
import json
import os
import socket
import sys
from pathlib import Path

outside, dummy_home = map(Path, sys.argv[1:])
for path in (outside, dummy_home / ".ssh" / "id_ed25519", Path("escape-link")):
    try:
        path.read_bytes()
    except OSError as error:
        assert error.errno in (errno.ENOENT, errno.EACCES), (path, error)
    else:
        raise AssertionError("Outside dummy unexpectedly readable")
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as error:
    assert error.errno == errno.EPERM, error
else:
    raise AssertionError("Socket creation unexpectedly succeeded")
assert "SAFESHELL_DUMMY_SECRET" not in os.environ
status = Path("/proc/self/status").read_text()
assert "NoNewPrivs:\t1" in status and "CapEff:\t0000000000000000" in status
assert "Seccomp:\t2" in status
try:
    profile = Path("/proc/self/attr/current").read_text().strip()
except OSError:
    profile = "unavailable"
Path("boundary-results.json").write_text(
    json.dumps(
        {
            "outside_denied": True,
            "dummy_home_denied": True,
            "symlink_escape_denied": True,
            "socket_denied": True,
            "environment_excluded": True,
            "no_new_privileges": True,
            "apparmor_profile": profile,
        },
        indent=2,
    )
    + "\n"
)
print("Dummy boundary checks passed; this is not a security audit.")
