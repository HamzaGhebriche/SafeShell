"""Exercise the actual pytest gate in subprocesses, including plugin-less output."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("terminal", [True, False])
def test_required_mode_rejects_skips(tmp_path, terminal):
    shutil.copyfile(Path(__file__).with_name("conftest.py"), tmp_path / "conftest.py")
    (tmp_path / "test_gate.py").write_text(
        "import pytest\ndef test_silent_skip(): pytest.skip('dummy skip')\n"
    )
    args = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "--confcutdir",
        str(tmp_path),
        str(tmp_path / "test_gate.py"),
    ]
    if not terminal:
        args += ["-p", "no:terminal"]
    result = subprocess.run(
        args,
        env=dict(os.environ, SAFESHELL_REQUIRE_BACKEND="1"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)


def test_required_mode_rejects_missing_boundary_tests(tmp_path):
    shutil.copyfile(Path(__file__).with_name("conftest.py"), tmp_path / "conftest.py")
    (tmp_path / "test_gate.py").write_text("def test_only_unit_tests(): pass\n")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "--confcutdir",
            str(tmp_path),
            str(tmp_path / "test_gate.py"),
        ],
        env=dict(os.environ, SAFESHELL_REQUIRE_BACKEND="1"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)


def test_validation_evidence_cannot_silently_reuse_stale_results(tmp_path):
    from tools.debian_vm import prepare_results
    from tools.validate_linux import clear_current_evidence

    output = tmp_path / "evidence"
    prepare_results(output)
    old = output / "pytest.xml"
    old.write_text("previous run")
    with pytest.raises(SystemExit, match="not empty"):
        prepare_results(output)
    assert old.read_text() == "previous run"
    clear_current_evidence(output)
    assert not old.exists()
