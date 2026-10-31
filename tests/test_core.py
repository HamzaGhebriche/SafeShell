import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from safeshell import analysis, audit, backend, policy
from safeshell.cli import main


@pytest.mark.parametrize(
    "source,expected",
    [
        ("printf '%s' 'a b'", ["printf", "%s", "a b"]),
        ('printf "|" ";" ""', ["printf", "|", ";", ""]),
        (r"echo a\ b", ["echo", "a b"]),
        ("echo '#not-comment' # comment", ["echo", "#not-comment"]),
    ],
)
def test_quotes(source, expected):
    commands, _ = analysis.parse_shell(source)
    assert commands[0].argv == expected


def test_grammar():
    commands, operators = analysis.parse_shell("cat < input | sort > output && echo done; true")
    assert len(commands) == 4
    assert operators == ["|", "&&", ";"]
    assert commands[1].redirects == [(">", "output")]


@pytest.mark.parametrize(
    "source",
    [
        "echo $(id)",
        "echo $HOME",
        "f() { id; }",
        "echo `id`",
        "echo a &",
        "a ||| b",
        "echo >",
        "echo |",
        "if true; then x; fi",
        "cat << EOF",
        "X=a echo hi",
        "echo 'x",
    ],
)
def test_unsupported_is_uncertain_and_denied(source):
    report = analysis.inspect([source], True)
    assert not report["syntax_supported"]
    assert not policy.evaluate(report, policy.Policy())["permitted"]


@pytest.mark.parametrize(
    "argv,rule",
    [
        (["sudo", "id"], "SS002"),
        (["rm", "-rf", "project"], "SS003"),
        (["cat", "/home/example/.ssh/id_rsa"], "SS004"),
        (["npm", "test"], "SS006"),
        (["docker", "--privileged"], "SS007"),
        (["base64", "-d"], "SS008"),
    ],
)
def test_rules(argv, rule):
    assert rule in {f["id"] for f in analysis.inspect(argv)["findings"]}


def test_remote_and_redirect_rules():
    assert "SS010" in {
        x["id"] for x in analysis.inspect(["curl https://example.invalid | bash"], True)["findings"]
    }
    assert "SS005" in {
        x["id"] for x in analysis.inspect(["echo x > /etc/example"], True)["findings"]
    }
    assert "SS009" in {x["id"] for x in analysis.inspect(["echo x > .bashrc"], True)["findings"]}


def test_argv_not_reparsed():
    report = analysis.inspect(["printf", "a b", "|", "$(id)"])
    assert report["mode"] == "argv"
    assert report["predicted_behavior"] == ["Program invocation"]


@pytest.mark.parametrize(
    "content",
    [
        'network="on"',
        "unexpected=true",
        'confirmation="never"',
        "version=true",
        'environment=["SSH_AUTH_SOCK"]',
        "hard_denied=[]",
        'workspace=".."',
        'preset="strict"\nconfirmation="risk"',
        'audit="raw"',
        "preset=[]",
        'hard_denied=["privilege","credentials","containers","filesystem-write"]',
    ],
)
def test_policy_rejects_expansion(tmp_path, content):
    (tmp_path / ".safeshell.toml").write_text(content)
    with pytest.raises((ValueError, TypeError)):
        policy.load(tmp_path)


@pytest.mark.parametrize("preset", list(policy.PRESETS))
def test_presets(tmp_path, preset):
    (tmp_path / ".safeshell.toml").write_text(policy.template(preset))
    assert policy.load(tmp_path).network == "off"


def test_policy_defaults_and_narrowing(tmp_path):
    assert policy.load(tmp_path).hard_denied == ["privilege", "credentials", "containers"]
    path = tmp_path / "explicit.toml"
    path.write_text('hard_denied=["privilege","credentials","containers","network"]')
    decision = policy.evaluate(analysis.inspect(["curl", "x"]), policy.load(tmp_path, path))
    assert decision["denials"] == ["network"]


def test_environment_is_conservative(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "dummy-secret")
    monkeypatch.setenv("PATH", "/evil")
    monkeypatch.setenv("LD_PRELOAD", "/evil.so")
    env = policy.environment(policy.Policy())
    assert "AWS_SECRET_ACCESS_KEY" not in env and "LD_PRELOAD" not in env
    assert env["PATH"] == "/usr/bin:/bin"


def test_terminal_escape():
    escaped = audit.safe("\x1b[31m\x07\r\n\u202eevil")
    assert "\x1b" not in escaped and "\u202e" not in escaped
    assert "\\u001b" in escaped


def test_private_history_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFESHELL_STATE_DIR", str(tmp_path / "history"))
    report = analysis.inspect(["echo", "DUMMY_SECRET"])
    record = audit.new_record(["echo", "DUMMY_SECRET"], report, {}, {}, "redacted")
    audit.save(record)
    assert "DUMMY_SECRET" not in json.dumps(audit.read(record["id"]))
    assert audit.records()[0]["id"] == record["id"]
    with pytest.raises(ValueError):
        audit.read("../other")
    audit.delete(record["id"])
    assert audit.records() == []


def invoke(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["safeshell", *args])
    code = main()
    return code, capsys.readouterr()


def test_cli_fail_closed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAFESHELL_STATE_DIR", str(tmp_path / "history"))
    with (
        patch.object(
            backend, "discover", return_value=backend.Capability(False, "none", "dummy unavailable")
        ),
        patch.object(subprocess, "Popen") as launch,
    ):
        code, output = invoke(
            monkeypatch,
            capsys,
            "run",
            "--json",
            "--workspace",
            str(tmp_path),
            "--yes",
            "--",
            "echo",
            "hi",
        )
        assert code == 4
        assert json.loads(output.out)["session"]["status"] == "backend-unavailable"
        launch.assert_not_called()


def test_noninteractive_confirmation_and_denial(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAFESHELL_STATE_DIR", str(tmp_path / "history"))
    with (
        patch.object(
            backend, "discover", return_value=backend.Capability(True, "bubblewrap", "mock")
        ),
        patch.object(backend, "run") as launch,
    ):
        code, output = invoke(
            monkeypatch, capsys, "run", "--json", "--workspace", str(tmp_path), "--", "npm", "test"
        )
        assert code == 3
        assert json.loads(output.out)["session"]["status"] == "confirmation-required"
        code, _ = invoke(
            monkeypatch,
            capsys,
            "run",
            "--json",
            "--yes",
            "--workspace",
            str(tmp_path),
            "--",
            "sudo",
            "id",
        )
        assert code == 3
        launch.assert_not_called()


def test_child_arguments_and_status(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAFESHELL_STATE_DIR", str(tmp_path / "history"))
    with (
        patch.object(
            backend, "discover", return_value=backend.Capability(True, "bubblewrap", "mock")
        ),
        patch.object(backend, "run", return_value=17) as launch,
    ):
        code, output = invoke(
            monkeypatch,
            capsys,
            "run",
            "--json",
            "--workspace",
            str(tmp_path),
            "--",
            "printf",
            "a b",
            "|",
            "",
        )
        assert code == 17, output
        assert launch.call_args.args[1] == ["printf", "a b", "|", ""]
        assert json.loads(output.out)["session"]["exit_code"] == 17


def test_inspection_never_launches(monkeypatch, capsys):
    with (
        patch.object(backend, "discover", return_value=backend.Capability(False, "none", "mock")),
        patch.object(backend, "run") as launch,
    ):
        code, output = invoke(
            monkeypatch,
            capsys,
            "explain",
            "--json",
            "--shell",
            "bash",
            "--",
            "touch should-not-exist",
        )
        assert code == 0 and json.loads(output.out)["schema_version"] == 1
        launch.assert_not_called()


def test_workspace_rejects_dangerous_roots():
    for path in (Path.home(), Path(Path.cwd().anchor)):
        with pytest.raises(ValueError):
            backend.workspace_path(str(path))


def test_backend_availability_without_launch():
    with (
        patch.object(backend.sys, "platform", "win32"),
        patch.object(subprocess, "Popen") as launch,
    ):
        assert not backend.discover().available
        launch.assert_not_called()


def test_privacy_expansion_needs_review(tmp_path):
    (tmp_path / ".safeshell.toml").write_text('audit="redacted"\nenvironment=["TZ"]')
    with pytest.raises(ValueError, match="review-policy"):
        policy.load(tmp_path)
    assert policy.load(tmp_path, reviewed=True).audit == "redacted"


def test_workspace_hardlink_rejected(tmp_path):
    source = tmp_path / "dummy"
    source.write_text("dummy")
    try:
        (tmp_path / "alias").hardlink_to(source)
    except OSError as exc:
        pytest.skip(f"Host cannot create test hardlinks: {exc}")
    with pytest.raises(ValueError, match="hardlinks"):
        backend.check_workspace_contents(tmp_path)


def test_hostile_history_rendering(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAFESHELL_STATE_DIR", str(tmp_path / "history"))
    report = analysis.inspect(["echo"])
    record = audit.new_record(["echo"], report, {}, {}, "metadata")
    record["command"] = "\x1b[2J\u202eFORGED"
    audit.save(record)
    code, output = invoke(monkeypatch, capsys, "history")
    assert code == 0 and "\x1b" not in output.out and "\\u001b" in output.out


def test_descriptor_syntax_denied():
    report = analysis.inspect(["echo x 2>err"], True)
    assert not report["syntax_supported"]


def test_hardlink_scan_rule(tmp_path):
    import stat
    from types import SimpleNamespace

    (tmp_path / "dummy").write_text("dummy")
    with patch.object(
        Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=2)
    ):
        with pytest.raises(ValueError, match="hardlinks"):
            backend.check_workspace_contents(tmp_path)


def test_launch_error_no_second_attempt(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAFESHELL_STATE_DIR", str(tmp_path / "history"))
    with (
        patch.object(
            backend, "discover", return_value=backend.Capability(True, "bubblewrap", "mock")
        ),
        patch.object(backend, "run", side_effect=RuntimeError("setup failed")) as launch,
    ):
        code, output = invoke(
            monkeypatch, capsys, "run", "--json", "--workspace", str(tmp_path), "--", "true"
        )
        assert code == 4
        assert json.loads(output.out)["session"]["status"] == "launch-failed"
        assert launch.call_count == 1


def test_launch_layout_and_argument_boundary(tmp_path):
    command = ["printf", "a b", "|", "", "$(id)", "--share-net"]
    with patch.object(
        backend.runtime, "profile", return_value=(("/usr/bin/true", "/usr/bin/true"),)
    ):
        args = backend.launch_args("/usr/bin/bwrap", tmp_path, command, 17)
    boundary = args.index("--")
    assert args[boundary + 1 :] == command
    assert "--unshare-user" in args[:boundary]
    assert "--disable-userns" in args[:boundary]
    assert "--share-net" not in args[:boundary]
    assert "--dev-bind" not in args[:boundary]
    assert args[boundary - 2 : boundary] == ["--remount-ro", "/"]


def test_unreadable_workspace_scan_fails_closed(tmp_path):
    def unreadable(root, **kwargs):
        kwargs["onerror"](PermissionError("dummy permission failure"))
        return iter(())

    with patch.object(backend.os, "walk", side_effect=unreadable):
        with pytest.raises(ValueError, match="Cannot inspect"):
            backend.check_workspace_contents(tmp_path)


def test_probe_not_described_as_effective_enforcement():
    result = backend.describe(backend.Capability(True, "bubblewrap", "mock smoke probe"))
    assert result["effective_enforcement"] is None
    assert result["probed_restrictions"] is not None


def test_missing_required_seccomp_rule_fails_closed(tmp_path):
    from types import SimpleNamespace
    from unittest.mock import Mock
    import tempfile

    lib = SimpleNamespace(
        **{
            name: Mock()
            for name in (
                "seccomp_init",
                "seccomp_syscall_resolve_name",
                "seccomp_rule_add",
                "seccomp_export_bpf",
                "seccomp_release",
            )
        }
    )
    lib.seccomp_init.return_value = 123
    lib.seccomp_syscall_resolve_name.return_value = -1
    original = tempfile.TemporaryFile
    with (
        patch.object(backend.ctypes, "CDLL", return_value=lib),
        patch.object(backend.tempfile, "TemporaryFile", side_effect=lambda: original(dir=tmp_path)),
    ):
        with pytest.raises(RuntimeError, match="mandatory syscall: socket"):
            backend.seccomp_file()
    lib.seccomp_release.assert_called_once_with(123)


@pytest.mark.parametrize("timeout,limit", [(0, 1024), (True, 1024), (1, 0), (1, 67108865)])
def test_invalid_limits_never_launch(timeout, limit, tmp_path):
    with patch.object(backend, "discover") as discover:
        with pytest.raises(ValueError):
            backend.run(tmp_path, ["true"], policy.Policy(), lambda b: None, timeout, limit)
        discover.assert_not_called()


def test_output_limit_status_unambiguous(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAFESHELL_STATE_DIR", str(tmp_path / "history"))
    with (
        patch.object(
            backend, "discover", return_value=backend.Capability(True, "bubblewrap", "mock")
        ),
        patch.object(backend, "run", return_value=backend.ExitStatus(125, "output-limit")),
    ):
        code, output = invoke(
            monkeypatch,
            capsys,
            "run",
            "--json",
            "--max-output-bytes",
            "1024",
            "--workspace",
            str(tmp_path),
            "--",
            "true",
        )
    session = json.loads(output.out)["session"]
    assert code == 125 and session["status"] == "output-limit"
    assert session["limits"]["output_bytes"] == 1024


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO fixture unsupported on Windows")
def test_nonregular_history_record_cannot_block(tmp_path):
    import os
    import uuid

    state = tmp_path / "history"
    state.mkdir(mode=0o700)
    session_id = str(uuid.uuid4())
    os.mkfifo(state / (session_id + ".json"))
    # A subprocess deadline makes this regression bounded if a FIFO is opened.
    command = [sys.executable, "-m", "safeshell", "history", "show", session_id, "--json"]
    result = subprocess.run(
        command,
        env=dict(os.environ, SAFESHELL_STATE_DIR=str(state)),
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "Invalid history record"
