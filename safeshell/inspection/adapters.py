"""Offline scanner adapters with bounded pipes, deadlines and sanitized environments."""

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Protocol

from .models import EngineResult, Finding


class Adapter(Protocol):
    source: str

    def scan(self, target: Path, cache: Path) -> EngineResult: ...


def bounded_run(
    argv: list[str], cwd: Path, env: dict[str, str], timeout=60, limit=4194304
) -> tuple[int, bytes, bytes]:
    """Each pipe has a bounded buffer; overflow kills the scanner and invalidates output."""
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    with subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    ) as process:

        def read(stream, buffer):
            while block := stream.read(8192):
                remaining = max(0, limit - len(buffer))
                buffer.extend(block[:remaining])
                if len(block) > remaining:
                    overflow.set()
                    process.kill()
                    break

        workers = [
            threading.Thread(target=read, args=(stream, buffer), daemon=True)
            for stream, buffer in zip((process.stdout, process.stderr), buffers)
        ]
        for worker in workers:
            worker.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        finally:
            for worker in workers:
                worker.join(timeout=2)
        if overflow.is_set() or any(w.is_alive() for w in workers):
            raise ValueError("Scanner output exceeded limit or pipe did not close")
        return process.returncode, bytes(buffers[0]), bytes(buffers[1])


class JsonAdapter:
    source = ""
    binary = ""

    def arguments(self, target: Path, cache: Path) -> list[str]:
        raise NotImplementedError

    def normalize(self, data: dict) -> list[Finding]:
        raise NotImplementedError

    def scan(self, target: Path, cache: Path) -> EngineResult:
        executable = shutil.which(self.binary)
        if not executable:
            return EngineResult(self.source, "UNAVAILABLE", reason="Binary not installed")
        executable_path = Path(executable).resolve()
        # PATH entries inside the target, relative binaries and shell launchers are untrusted.
        if executable_path.is_relative_to(target) or executable_path.suffix.lower() in {
            ".cmd",
            ".bat",
        }:
            return EngineResult(
                self.source, "UNAVAILABLE", reason="Untrusted scanner location/type"
            )
        home = cache / "home"
        home.mkdir(exist_ok=True)
        env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR"}}
        env.update(
            HOME=str(home),
            USERPROFILE=str(home),
            XDG_CONFIG_HOME=str(home),
            XDG_CACHE_HOME=str(cache),
            TMPDIR=str(home),
            TMP=str(home),
            TEMP=str(home),
            OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(cache / "osv"),
            PATH=str(executable_path.parent),
            NO_COLOR="1",
        )
        version = None
        scan_exit = None
        try:
            code, stdout, _ = bounded_run([str(executable_path), "--version"], home, env, 5, 8192)
            if code == 0:
                version = stdout.decode("utf-8", "replace").strip()[:300]
            code, stdout, stderr = bounded_run(
                [str(executable_path), *self.arguments(target, cache)], home, env
            )
            scan_exit = code
            if not stdout.strip():
                diagnostic = "no JSON output"
                if b"first run" in stderr or b"local db" in stderr.lower():
                    diagnostic = (
                        "offline database unavailable; prepare the trusted cache separately"
                    )
                elif b"No package sources found" in stderr:
                    diagnostic = "no supported dependency sources found"
                return EngineResult(
                    self.source,
                    "PARTIAL",
                    reason=f"Scanner exit {code}: {diagnostic}",
                    version=version,
                    exit_code=code,
                )
            data = json.loads(stdout)
            findings = self.normalize(data)
            accepted = code == 0 or (self.source == "OSV-Scanner" and code == 1 and findings)
            return EngineResult(
                self.source,
                "COMPLETE" if accepted else "PARTIAL",
                findings,
                "" if accepted else f"Scanner exit {code}; output may be incomplete",
                version,
                code,
            )
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            RecursionError,
            subprocess.TimeoutExpired,
        ) as exc:
            reason = (
                f"Scanner timed out after {exc.timeout}s"
                if isinstance(exc, subprocess.TimeoutExpired)
                else type(exc).__name__
            )
            if scan_exit is not None:
                reason = f"Scanner exit {scan_exit}: {reason}"
            return EngineResult(
                self.source, "PARTIAL", reason=reason, version=version, exit_code=scan_exit
            )

    def finding(self, category, title, file=None, identifiers=None, **kwargs):
        return Finding(
            "",
            self.source,
            category,
            kwargs.pop("severity", "UNKNOWN"),
            kwargs.pop("confidence", "HIGH"),
            title,
            file=file,
            identifiers=identifiers or [],
            **kwargs,
        )


class Trivy(JsonAdapter):
    source, binary = "Trivy", "trivy"

    def arguments(self, target, cache):
        return [
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln,secret,misconfig",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--skip-version-check",
            "--disable-telemetry",
            "--cache-dir",
            str(cache / "trivy"),
            "--ignorefile",
            str(cache / "empty-ignore"),
            str(target),
        ]

    def normalize(self, data):
        if not isinstance(data, dict) or ("Results" not in data and data.get("SchemaVersion") != 2):
            raise ValueError("Unrecognized Trivy schema")
        findings = []
        for result in data.get("Results") or []:
            file = result.get("Target")
            for raw in result.get("Vulnerabilities") or []:
                findings.append(
                    self.finding(
                        "vulnerability",
                        raw.get("Title", "Dependency vulnerability"),
                        file,
                        [raw["VulnerabilityID"]],
                        severity=raw.get("Severity", "UNKNOWN"),
                        package=raw.get("PkgName"),
                        installed_version=raw.get("InstalledVersion"),
                        fixed_version=raw.get("FixedVersion"),
                        evidence=raw,
                        metadata={"ecosystem": result.get("Type")},
                    )
                )
            for key, category in [("Secrets", "secret"), ("Misconfigurations", "misconfiguration")]:
                for raw in result.get(key) or []:
                    # Never include matched secret values/snippets in the report.
                    identifiers = [str(raw.get("ID", raw.get("RuleID", "unknown")))]
                    findings.append(
                        self.finding(
                            category,
                            raw.get("Title", category),
                            file,
                            identifiers,
                            severity=raw.get("Severity", "UNKNOWN"),
                            line=raw.get("StartLine")
                            or raw.get("CauseMetadata", {}).get("StartLine"),
                            evidence={
                                "identifiers": identifiers,
                                "status": raw.get("Status"),
                                "secret_content_redacted": category == "secret",
                            },
                        )
                    )
        return findings


class OSV(JsonAdapter):
    source, binary = "OSV-Scanner", "osv-scanner"

    def arguments(self, target, cache):
        return [
            "scan",
            "source",
            "--offline",
            "--format",
            "json",
            "--recursive",
            "--no-ignore",
            str(target),
        ]

    def normalize(self, data):
        if not isinstance(data, dict) or "results" not in data:
            raise ValueError("Unrecognized OSV schema")
        findings = []
        for result in data["results"] or []:
            for entry in result.get("packages", []):
                package = entry["package"]
                for raw in entry.get("vulnerabilities", []):
                    fixed, ranges = [], []
                    for affected in raw.get("affected", []):
                        ranges.extend(affected.get("ranges", []))
                        for version_range in affected.get("ranges", []):
                            fixed.extend(
                                e["fixed"] for e in version_range.get("events", []) if "fixed" in e
                            )
                    findings.append(
                        self.finding(
                            "vulnerability",
                            raw.get("summary", raw["id"]),
                            result.get("source", {}).get("path"),
                            [raw["id"], *raw.get("aliases", [])],
                            package=package.get("name"),
                            installed_version=package.get("version"),
                            fixed_version=", ".join(fixed) or None,
                            evidence=raw,
                            severity=raw.get("database_specific", {}).get("severity", "UNKNOWN"),
                            metadata={
                                "ecosystem": package.get("ecosystem"),
                                "affected_ranges": ranges,
                            },
                        )
                    )
        return findings


class GatedAdapter:
    def __init__(self, source: str, reason: str):
        self.source, self.reason = source, reason

    def scan(self, target, cache):
        return EngineResult(self.source, "UNAVAILABLE", reason=self.reason)


def default_adapters() -> list[Adapter]:
    return [
        Trivy(),
        OSV(),
        GatedAdapter(
            "YARA-X", "Feature gated: requires reviewed rules and validated JSON contract"
        ),
        GatedAdapter(
            "Scorecard",
            "Feature gated: local target has no verified GitHub identity; network disabled",
        ),
    ]
