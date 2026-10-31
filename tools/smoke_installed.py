"""Offline wheel install into a fresh venv; exercise only the installed CLI from a new cwd."""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--require-backend", action="store_true")
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    report = {
        "wheel": wheel.name,
        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "workflows": {},
    }
    with tempfile.TemporaryDirectory(prefix="safeshell-installed-") as directory:
        root = Path(directory)
        install, project, home = root / "venv", root / "project", root / "home"
        project.mkdir()
        home.mkdir()
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG")
        }
        environment.update(
            HOME=str(home),
            USERPROFILE=str(home),
            SAFESHELL_STATE_DIR=str(root / "history"),
            PYTHONNOUSERSITE="1",
        )
        venv.EnvBuilder(with_pip=True, clear=False).create(install)
        binary = install / ("Scripts" if os.name == "nt" else "bin")
        python = binary / ("python.exe" if os.name == "nt" else "python")
        cli = binary / ("safeshell.exe" if os.name == "nt" else "safeshell")
        subprocess.run(
            [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
            check=True,
            cwd=project,
            env=environment,
            capture_output=True,
            timeout=120,
        )
        package_details = subprocess.check_output(
            [
                str(python),
                "-c",
                "import safeshell,json,importlib.metadata; print(json.dumps({'file':safeshell.__file__,'version':safeshell.__version__,'metadata':importlib.metadata.version('safeshell-cli')}))",
            ],
            cwd=project,
            env=environment,
            text=True,
        ).strip()
        package_info = json.loads(package_details)
        package = package_info["file"]
        assert package_info["version"] == package_info["metadata"] == "0.1.0a1"
        assert Path(package).is_relative_to(install), (
            "Source checkout shadowed the installed package"
        )

        def invoke(name, arguments, expected=0, machine=True):
            result = subprocess.run(
                [str(cli), *arguments],
                cwd=project,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            assert result.returncode == expected, (
                name,
                result.returncode,
                result.stdout,
                result.stderr,
            )
            report["workflows"][name] = result.returncode
            return json.loads(result.stdout) if machine else result.stdout.strip()

        version = invoke("version", ["--version"], machine=False)
        assert version == "0.1.0a1"
        report["version"] = version
        preview = invoke(
            "explain",
            [
                "explain",
                "--json",
                "--shell",
                "bash",
                "--",
                "curl https://example.invalid/install.sh | bash",
            ],
        )
        assert "SS010" in {f["id"] for f in preview["findings"]}
        script = project / "inspect.sh"
        script.write_text("touch inspect-only-marker")
        invoke("explain-script", ["explain", "--json", "--script", str(script)])
        assert not (project / "inspect-only-marker").exists()
        invoke("policy-init", ["policy", "init", "--preset", "offline", "--json"])
        assert (
            invoke("policy-validate", ["policy", "validate", "--json"])["policy"]["network"]
            == "off"
        )
        doctor = subprocess.run(
            [str(cli), "doctor", "--json"],
            cwd=project,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        details = json.loads(doctor.stdout)
        available = details["available"]
        if args.require_backend:
            assert available, details["reason"]
        assert doctor.returncode == (0 if available else 4)
        report["workflows"]["doctor"] = doctor.returncode
        report["backend_available"] = available
        report["runtime_files"] = len(details.get("runtime_manifest", {}).get("files", []))
        denied = invoke("policy-denial", ["run", "--json", "--yes", "--", "sudo", "id"], 3)
        assert denied["session"]["status"] == "denied"
        assert "privilege" in denied["report"]["decision"]["denials"]
        result = invoke(
            "run",
            [
                "run",
                "--json",
                "--yes",
                "--timeout",
                "10",
                "--max-output-bytes",
                "4096",
                "--",
                "/bin/sh",
                "-c",
                "printf 'hello from sandbox' > hello.txt; cat hello.txt",
            ],
            0 if available else 4,
        )
        session = result["session"]["id"]
        if available:
            assert (project / "hello.txt").read_text() == "hello from sandbox"
            limited = invoke(
                "output-limit",
                [
                    "run",
                    "--json",
                    "--yes",
                    "--max-output-bytes",
                    "32",
                    "--",
                    "/usr/bin/python3",
                    "-c",
                    "print('x'*10000)",
                ],
                125,
            )
            assert limited["session"]["status"] == "output-limit"
            timed = invoke(
                "timeout", ["run", "--json", "--timeout", "1", "--", "/usr/bin/sleep", "3"], 124
            )
            assert timed["session"]["status"] == "timed-out"
        else:
            assert not (project / "hello.txt").exists()
        assert session in {s["id"] for s in invoke("history", ["history", "--json"])["sessions"]}
        assert invoke("history-show", ["history", "show", session, "--json"])["id"] == session
        invoke("history-delete", ["history", "delete", session, "--json"])
        assert session not in {
            s["id"] for s in invoke("history-after-delete", ["history", "--json"])["sessions"]
        }
    report["clean_environment"] = (
        "Fresh venv without system site packages; unrelated cwd; no network install; removed afterward"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
