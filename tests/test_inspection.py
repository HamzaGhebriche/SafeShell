import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from safeshell.cli import main
from safeshell.inspection.adapters import OSV, Trivy, bounded_run
from safeshell.inspection.benchmark import evaluate, metrics
from safeshell.inspection.decision import decide, deduplicate
from safeshell.inspection.engine import inspect_repository, render_map
from safeshell.inspection.inventory import inventory, snapshot
from safeshell.inspection.models import EngineResult, Finding, Graph


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_static_chain_never_executes(tmp_path):
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"node scripts/setup.js"}}')
    write(tmp_path, "scripts/setup.js", 'spawn("powershell", ["scripts/setup.ps1"]);')
    write(
        tmp_path,
        "scripts/setup.ps1",
        "Invoke-WebRequest https://example.invalid/a\nGet-Content ~/.aws/credentials",
    )
    with patch("subprocess.Popen", side_effect=AssertionError("Must not launch")):
        report = inspect_repository(tmp_path, [])
    assert report["verdict"]["verdict"] == "HIGH RISK"
    assert report["correlations"][0]["rule"] == "SS-CORR-001"
    assert "setup.ps1" in render_map(report)
    assert report["schema_version"] == "inspection-1"


@pytest.mark.parametrize(
    "name,text",
    [
        ("package.json", '{"scripts":{"test":"bash test.sh"}}'),
        ("pyproject.toml", '[project.scripts]\nhello="hello:main"'),
        ("setup.py", 'print("never run")'),
        ("setup.cfg", "[options.entry_points]\nconsole_scripts=hello=hello:main"),
        ("Dockerfile", 'RUN curl https://example.invalid/a\nENTRYPOINT ["sh"]\nCMD ["x"]'),
        ("Makefile", "all:\n\techo hello"),
        (
            ".github/workflows/test.yml",
            "steps:\n  - run: echo hello\n  - uses: example/action@main",
        ),
        (".vscode/tasks.json", '{"tasks":[{"command":"echo hi"}]}'),
        (".claude/settings.json", '{"hooks":{"Start":[{"command":"echo hi"}]}}'),
    ],
)
def test_surfaces(tmp_path, name, text):
    write(tmp_path, name, text)
    report = inspect_repository(tmp_path, [])
    assert any(f["category"] == "execution" for f in report["findings"])


@pytest.mark.parametrize(
    "name,text,category",
    [
        ("x.ps1", "powershell -EncodedCommand " + "A" * 60, "obfuscation"),
        ("x.sh", "wget https://example.invalid/a", "external_download"),
        ("x.bat", "schtasks /create", "persistence"),
        ("x.cmd", "diskpart", "destructive"),
        ("x.py", 'open("~/.ssh/id_rsa")', "sensitive_access"),
    ],
)
def test_behavior(tmp_path, name, text, category):
    write(tmp_path, name, text)
    assert category in {f["category"] for f in inspect_repository(tmp_path, [])["findings"]}


def test_unrelated_signals_not_correlated(tmp_path):
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"node a.js"}}')
    write(tmp_path, "a.js", 'fetch("https://example.invalid/a")')
    write(tmp_path, "unrelated.ps1", "Get-Content ~/.aws/credentials")
    assert inspect_repository(tmp_path, [])["verdict"]["verdict"] != "HIGH RISK"


def test_cycles_and_missing_files(tmp_path):
    graph = Graph()
    a, b = graph.node("file", "a"), graph.node("file", "b")
    graph.edge(a, b, "invokes")
    graph.edge(b, a, "invokes")
    assert graph.reachable(a) == {a, b}
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"node missing.js"}}')
    assert inspect_repository(tmp_path, [])["verdict"]["verdict"] == "UNKNOWN"


@pytest.mark.parametrize(
    "name,content",
    [("package.json", "{"), ("pyproject.toml", "["), (".vscode/tasks.json", '{"tasks":null}')],
)
def test_malformed(tmp_path, name, content):
    write(tmp_path, name, content)
    assert inspect_repository(tmp_path, [])["coverage"]["gaps"]


def test_inventory_limits_and_configs(tmp_path):
    write(tmp_path, "big", "A" * 100)
    write(tmp_path, "trivy.yaml", "malicious configuration")
    assert inventory(tmp_path, max_file=10).gaps
    assert inventory(tmp_path, max_entries=1).gaps
    destination = tmp_path / "snapshot"
    destination.mkdir()
    snapshot(inventory(tmp_path), destination)
    assert not (destination / "trivy.yaml").exists()


def test_symlink_and_traversal(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    write(outside, "secret", "not read")
    target = tmp_path / "target"
    target.mkdir()
    # Mock a link entry on systems where creating symlinks needs privileges.
    with patch.object(Path, "is_symlink", return_value=True), pytest.raises(ValueError):
        inventory(target)
    write(target, "package.json", '{"scripts":{"install":"node ../../outside/secret.js"}}')
    report = inspect_repository(target, [])
    assert not any(n["file"] == "outside/secret.js" for n in report["execution_graph"]["nodes"])


def test_adapter_missing(tmp_path):
    with patch("shutil.which", return_value=None):
        assert OSV().scan(tmp_path, tmp_path).status == "UNAVAILABLE"


@pytest.mark.parametrize(
    "failure", [ValueError("bad JSON"), subprocess.TimeoutExpired("scanner", 1), OSError("missing")]
)
def test_adapter_failure(tmp_path, failure):
    with (
        patch("shutil.which", return_value=sys.executable),
        patch("safeshell.inspection.adapters.bounded_run", side_effect=failure),
    ):
        assert OSV().scan(tmp_path, tmp_path).status == "PARTIAL"


@pytest.mark.parametrize(
    "code,body,status",
    [
        (0, '{"results":[]}', "COMPLETE"),
        (2, '{"results":[]}', "PARTIAL"),
        (0, "{}", "PARTIAL"),
        (0, "{", "PARTIAL"),
    ],
)
def test_adapter_outputs(tmp_path, code, body, status):
    calls = [(0, b"scanner v2", b""), (code, body.encode(), b"bounded stderr")]
    with (
        patch("shutil.which", return_value=sys.executable),
        patch("safeshell.inspection.adapters.bounded_run", side_effect=calls) as run,
    ):
        result = OSV().scan(tmp_path, tmp_path)
    assert result.status == status
    assert result.version == "scanner v2"
    assert "AWS_SECRET_ACCESS_KEY" not in run.call_args.args[2]
    assert "--offline" in run.call_args.args[0]


def test_normalize_and_deduplicate():
    trivy = Trivy().normalize(
        {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "x",
                            "InstalledVersion": "1",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        }
    )
    osv = OSV().normalize(
        {
            "results": [
                {
                    "source": {"path": "package-lock.json"},
                    "packages": [
                        {
                            "package": {"name": "x", "version": "1", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-example",
                                    "aliases": ["CVE-2026-0001"],
                                    "affected": [{"ranges": [{"events": [{"fixed": "2"}]}]}],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    findings, duplicates = deduplicate(trivy + osv)
    assert len(findings) == 1 and duplicates == 1
    assert findings[0].metadata["additional_evidence"][0]["fixed_version"] == "2"
    assert decide(findings, Graph(), False)[1]["verdict"] == "CAUTION"


def test_secrets_redacted():
    findings = Trivy().normalize(
        {"Results": [{"Secrets": [{"RuleID": "secret", "Match": "DO-NOT-LEAK"}]}]}
    )
    assert "DO-NOT-LEAK" not in str(findings)


def test_verdicts():
    assert decide([], Graph(), False)[1]["verdict"] == "LOW RISK"
    assert decide([], Graph(), True)[1]["verdict"] == "UNKNOWN"
    finding = Finding("x", "Scorecard", "repository_posture", "HIGH", "CONTEXTUAL", "weak")
    assert decide([finding], Graph(), False)[1]["verdict"] == "CAUTION"


def test_bounded_process(tmp_path):
    env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR"}}
    with pytest.raises(ValueError, match="output exceeded"):
        bounded_run([sys.executable, "-c", 'print("x" * 20000)'], tmp_path, env, 5, 100)
    with pytest.raises(subprocess.TimeoutExpired):
        bounded_run([sys.executable, "-c", "import time; time.sleep(5)"], tmp_path, env, 0.1)


def test_benchmark():
    result = evaluate()
    assert len(result["samples"]) == 7
    assert result["metrics"]["SafeShell"]["true_positives"] >= 1
    assert metrics([True, False], [False, True])["false_negatives"] == 1
    assert metrics([], [])["precision"] is None
    assert all(row["verdict"] == row["expected_verdict"] for row in result["samples"])
    assert result["samples"][1]["baselines"]["OSV-Scanner"]


def test_reachable_signature_and_isolated_signature(tmp_path):
    class Signature:
        source = "YARA-X"

        def scan(self, target, cache):
            return EngineResult(
                self.source,
                "COMPLETE",
                [
                    Finding(
                        "test",
                        self.source,
                        "suspicious_file",
                        "HIGH",
                        "HIGH",
                        "Reviewed synthetic signature",
                        file="research.ps1",
                        identifiers=["synthetic-rule"],
                    )
                ],
            )

    write(tmp_path, "research.ps1", "Write-Output synthetic")
    assert inspect_repository(tmp_path, [Signature()])["verdict"]["verdict"] == "UNKNOWN"
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"powershell research.ps1"}}')
    report = inspect_repository(tmp_path, [Signature()])
    assert report["verdict"]["verdict"] == "HIGH RISK"
    assert report["correlations"][0]["rule"] == "SS-CORR-002"
    assert report["findings"][-1]["execution_relevant"]


def test_native_analysis_limit(tmp_path):
    write(tmp_path, "large.sh", "echo hi\n" * 2100)
    assert any("truncated" in gap for gap in inspect_repository(tmp_path, [])["coverage"]["gaps"])


def test_target_cannot_supply_scanner_or_cache(tmp_path):
    write(tmp_path, "scanner", "not executed")
    with patch("shutil.which", return_value=str(tmp_path / "scanner")):
        report = inspect_repository(tmp_path)
    assert report["engines"][1]["status"] == "UNAVAILABLE"
    with pytest.raises(ValueError, match="outside"):
        inspect_repository(tmp_path, [], cache=tmp_path / "cache")


def test_trivy_clean_output():
    assert Trivy().normalize({"SchemaVersion": 2}) == []


def test_transitive_aliases_and_distinct_versions():
    def item(ids, version="1"):
        return Finding(
            "",
            "test",
            "vulnerability",
            "HIGH",
            "HIGH",
            "test",
            identifiers=ids,
            package="pkg",
            installed_version=version,
        )

    findings, duplicates = deduplicate(
        [item(["CVE-A"]), item(["GHSA-A"]), item(["CVE-A", "GHSA-A"]), item(["CVE-A"], "2")]
    )
    assert len(findings) == 2 and duplicates == 2
    assert findings[0].identifiers == ["CVE-A", "GHSA-A"]


def test_osv_finding_exit_one_is_complete(tmp_path):
    body = json.dumps(
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "x", "version": "1"},
                            "vulnerabilities": [{"id": "OSV-SYNTHETIC"}],
                        }
                    ]
                }
            ]
        }
    ).encode()
    with (
        patch("shutil.which", return_value=sys.executable),
        patch(
            "safeshell.inspection.adapters.bounded_run",
            side_effect=[(0, b"v2", b""), (1, body, b"")],
        ),
    ):
        assert OSV().scan(tmp_path, tmp_path).status == "COMPLETE"


@pytest.mark.parametrize("action", ["inspect", "map", "findings"])
def test_cli(tmp_path, monkeypatch, capsys, action):
    monkeypatch.setattr(sys, "argv", ["safeshell", action, str(tmp_path), "--format", "json"])
    with patch("shutil.which", return_value=None):
        assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"]["verdict"] == "UNKNOWN"


def test_cli_text_lines_and_escaped_untrusted_content(tmp_path, monkeypatch, capsys):
    write(
        tmp_path, "package.json", json.dumps({"scripts": {"postinstall": "echo \u001b[2J\nFORGED"}})
    )
    monkeypatch.setattr(sys, "argv", ["safeshell", "inspect", str(tmp_path), "--show-map"])
    with patch("shutil.which", return_value=None):
        assert main() == 0
    output = capsys.readouterr().out
    assert output.startswith("SafeShell Trust Check\nVerdict:")
    assert "\u001b" not in output and "\nFORGED" not in output
    assert "\\u001b" in output and "\\u000aFORGED" in output


def test_hostile_filename_is_argv_data(tmp_path):
    target = tmp_path / "$(touch injected); --flag"
    target.mkdir()
    args = Trivy().arguments(target, tmp_path)
    assert args[-1] == str(target)
    assert not (tmp_path / "injected").exists()


def test_partial_adapter_does_not_abort(tmp_path):
    class Broken:
        source = "broken"

        def scan(self, target, cache):
            raise ValueError("bad output")

    report = inspect_repository(tmp_path, [Broken()])
    assert report["engines"][-1]["status"] == "PARTIAL"
