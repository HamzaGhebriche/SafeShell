"""Run only in a disposable Linux VM/CI runner, as an unprivileged sudo user.

Creates an outside dummy under /usr/local (which must be absent in the guest) and a
root-owned helper in a separately selected temporary workspace. Runs the complete
test directory with a zero-skip gate, then removes the fixtures.
No host namespace/AppArmor/sysctl protections are changed.
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def call(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def clear_current_evidence(destination):
    for name in (
        "host.json",
        "doctor.json",
        "doctor.stderr",
        "runtime-manifest.json",
        "namespace-inventory.json",
        "pytest.xml",
    ):
        (destination / name).unlink(missing_ok=True)


def main():
    options = argparse.ArgumentParser(description=__doc__)
    options.add_argument(
        "--as-user",
        help="Root-only harness: drop probe/tests to an existing unprivileged account (for root-default WSL)",
    )
    args = options.parse_args()
    if platform.system() != "Linux":
        raise SystemExit(
            "Use a disposable Linux VM with an unprivileged account and passwordless sudo"
        )
    identity = {}
    privilege = ["sudo", "-n"]
    if os.geteuid() == 0:
        import pwd

        if not args.as_user:
            raise SystemExit(
                "Root harness requires --as-user with an existing unprivileged account"
            )
        account = pwd.getpwnam(args.as_user)
        if account.pw_uid == 0:
            raise SystemExit("Tests must not run as root")
        identity = {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": []}
        privilege = []
    elif args.as_user:
        raise SystemExit("--as-user is only for a root harness")
    destination = ROOT / "validation-results"
    destination.mkdir(exist_ok=True)
    clear_current_evidence(destination)
    metadata = {
        "platform": platform.platform(),
        "python": sys.version,
        "bubblewrap": subprocess.check_output(["/usr/bin/bwrap", "--version"], text=True).strip(),
        "test_uid": identity.get("user", os.getuid()),
    }
    (destination / "host.json").write_text(json.dumps(metadata, indent=2))
    fixture_directory = None
    setuid_directory = None
    try:
        # The helper only prints real/effective UID and exits. It cannot execute
        # commands or read/write files. The host control must genuinely elevate.
        with tempfile.TemporaryDirectory(prefix="safeshell-fixture-build-") as directory:
            source = Path(directory) / "euid.c"
            executable = Path(directory) / "euid"
            dummy = Path(directory) / "dummy"
            source.write_text(
                '#include <stdio.h>\n#include <unistd.h>\nint main(void) { printf("%lu %lu\\n", (unsigned long)getuid(), (unsigned long)geteuid()); return 0; }\n'
            )
            dummy.write_text("DUMMY-RUNTIME-UNCHANGED")
            call("cc", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(executable))
            call(*privilege, "mkdir", "-p", "/usr/local/libexec")
            fixture_directory = subprocess.check_output(
                [*privilege, "mktemp", "-d", "/usr/local/libexec/safeshell-validation.XXXXXXXX"],
                text=True,
            ).strip()
            if not re.fullmatch(
                r"/usr/local/libexec/safeshell-validation\.[A-Za-z0-9]{8}", fixture_directory
            ):
                raise RuntimeError("Unexpected fixture directory returned by mktemp")
            # mktemp creates 0700; traversal must work for the unprivileged test user.
            call(*privilege, "chmod", "0755", fixture_directory)
            setuid_directory = subprocess.check_output(
                [*privilege, "mktemp", "-d", "/tmp/safeshell-setuid.XXXXXXXX"], text=True
            ).strip()
            if not re.fullmatch(r"/tmp/safeshell-setuid\.[A-Za-z0-9]{8}", setuid_directory):
                raise RuntimeError("Unexpected setuid workspace")
            call(*privilege, "chmod", "0755", setuid_directory)
            helper = setuid_directory + "/euid"
            runtime_dummy = fixture_directory + "/dummy"
            call(
                *privilege,
                "install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "4755",
                str(executable),
                helper,
            )
            call(
                *privilege,
                "install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0666",
                str(dummy),
                runtime_dummy,
            )
        environment = dict(
            os.environ,
            SAFESHELL_REQUIRE_BACKEND="1",
            SAFESHELL_SETUID_FIXTURE=helper,
            SAFESHELL_RUNTIME_DUMMY=runtime_dummy,
        )
        probe = subprocess.run(
            [sys.executable, "-m", "safeshell", "doctor", "--json"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            **identity,
            check=False,
        )
        (destination / "doctor.json").write_text(probe.stdout)
        (destination / "doctor.stderr").write_text(probe.stderr)
        details = json.loads(probe.stdout) if probe.stdout else {}
        if details.get("runtime_manifest"):
            (destination / "runtime-manifest.json").write_text(
                json.dumps(details["runtime_manifest"], indent=2)
            )
        print(
            json.dumps({key: details.get(key) for key in ("available", "backend", "reason")}),
            flush=True,
        )
        if probe.returncode == 0:
            inventory = subprocess.run(
                [sys.executable, "tools/capture_inventory.py"],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                **identity,
                check=False,
            )
            (destination / "namespace-inventory.json").write_text(inventory.stdout)
            if inventory.returncode:
                raise RuntimeError(inventory.stderr)
            expected_profile = os.environ.get("SAFESHELL_EXPECT_APPARMOR_PROFILE")
            if (
                expected_profile
                and json.loads(inventory.stdout).get("apparmor_profile")
                != expected_profile + " (enforce)"
            ):
                raise RuntimeError("Expected AppArmor child confinement was not observed")
        # Still run tests if doctor fails: failures and zero-pass gate are evidence.
        with tempfile.TemporaryDirectory(prefix="safeshell-test-evidence-") as evidence:
            # Parent directory stays root-owned in a root harness, so the test
            # identity can write the report but cannot replace it with a symlink.
            Path(evidence).chmod(0o755)
            report = Path(evidence) / "pytest.xml"
            report.touch(mode=0o600)
            if identity:
                os.chown(report, identity["user"], identity["group"])
            tests = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-ra",
                    "-p",
                    "no:cacheprovider",
                    "--strict-markers",
                    "tests",
                    f"--junitxml={report}",
                ],
                cwd=ROOT,
                env=environment,
                **identity,
                check=False,
            )
            (destination / "pytest.xml").write_bytes(report.read_bytes())
        return tests.returncode or probe.returncode
    finally:
        if fixture_directory and re.fullmatch(
            r"/usr/local/libexec/safeshell-validation\.[A-Za-z0-9]{8}", fixture_directory
        ):
            call(
                *privilege,
                "rm",
                "-f",
                "--",
                fixture_directory + "/euid",
                fixture_directory + "/dummy",
            )
            call(*privilege, "rmdir", "--", fixture_directory)
        if setuid_directory and re.fullmatch(
            r"/tmp/safeshell-setuid\.[A-Za-z0-9]{8}", setuid_directory
        ):
            call(*privilege, "rm", "-f", "--", setuid_directory + "/euid")
            call(*privilege, "rmdir", "--", setuid_directory)


if __name__ == "__main__":
    raise SystemExit(main())
