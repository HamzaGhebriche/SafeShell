"""Controlled synthetic evaluation. Fixtures are written as data and never executed."""

import json
import tempfile
import time
from pathlib import Path

from .engine import inspect_repository
from .models import EngineResult, Finding

SAMPLES = [
    ("clean-synthetic", {}, [], "LOW RISK", False),
    ("vulnerable-training", {}, ["vulnerability"], "CAUTION", False),
    (
        "suspicious-install",
        {
            "package.json": '{"scripts":{"postinstall":"node setup.js"}}',
            "setup.js": 'fetch("https://example.invalid/a"); readFileSync("~/.aws/credentials");',
        },
        [],
        "HIGH RISK",
        True,
    ),
    (
        "synthetic-dangerous",
        {
            "package.json": '{"scripts":{"install":"powershell setup.ps1"}}',
            "setup.ps1": "Invoke-WebRequest https://example.invalid/a\nGet-Content ~/.aws/credentials",
        },
        [],
        "HIGH RISK",
        True,
    ),
    (
        "security-research",
        {
            "research.ps1": "Invoke-WebRequest https://example.invalid/a\nGet-Content ~/.aws/credentials"
        },
        ["suspicious_file"],
        "CAUTION",
        False,
    ),
    ("poor-hygiene", {}, ["repository_posture"], "CAUTION", False),
    ("dependency-only", {}, ["vulnerability", "vulnerability"], "CAUTION", False),
]


def metrics(expected: list[bool], predicted: list[bool]) -> dict:
    if len(expected) != len(predicted):
        raise ValueError("Label lengths differ")
    tp = sum(a and b for a, b in zip(expected, predicted))
    fp = sum(not a and b for a, b in zip(expected, predicted))
    tn = sum(not a and not b for a, b in zip(expected, predicted))
    fn = sum(a and not b for a, b in zip(expected, predicted))
    return dict(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=tp / (tp + fp) if tp + fp else None,
        recall=tp / (tp + fn) if tp + fn else None,
        false_positive_rate=fp / (fp + tn) if fp + tn else None,
    )


class RecordedAdapter:
    """Deterministic scanner evidence; never presented as real-engine measurements."""

    def __init__(self, source, categories):
        self.source, self.categories = source, categories

    def scan(self, target, cache):
        findings = []
        for category in self.categories:
            if (
                (category == "vulnerability" and self.source in {"Trivy", "OSV-Scanner"})
                or (category == "suspicious_file" and self.source == "YARA-X")
                or (category == "repository_posture" and self.source == "Scorecard")
            ):
                findings.append(
                    Finding(
                        "recorded",
                        self.source,
                        category,
                        "HIGH",
                        "MEDIUM",
                        "Synthetic benchmark evidence",
                        file="research.ps1" if category == "suspicious_file" else None,
                        identifiers=["CVE-SYNTHETIC-0001"],
                        package="synthetic",
                        installed_version="1",
                        metadata={"ecosystem": "npm"},
                    )
                )
        return EngineResult(self.source, "COMPLETE", findings, "Synthetic recorded evidence")


def evaluate() -> dict:
    rows = []
    sources = ["Trivy", "OSV-Scanner", "YARA-X", "Scorecard"]
    for name, files, categories, expected, dangerous in SAMPLES:
        with tempfile.TemporaryDirectory(prefix="safeshell-benchmark-") as directory:
            root = Path(directory)
            for path, text in files.items():
                (root / path).write_text(text, encoding="utf-8")
            started = time.monotonic()
            report = inspect_repository(
                root, [RecordedAdapter(source, categories) for source in sources]
            )
            engine_counts = {e["source"]: e for e in report["engines"]}
            baselines = {
                source: engine_counts[source]["high_severity_count"] > 0 for source in sources
            }
            baselines["uncorrelated_scanners"] = any(baselines.values())
            rows.append(
                dict(
                    sample=name,
                    expected_verdict=expected,
                    verdict=report["verdict"]["verdict"],
                    expected_high_risk=dangerous,
                    baselines=baselines,
                    engines={e["source"]: e["status"] for e in report["engines"]},
                    findings_by_source={
                        source: engine_counts[source]["finding_count"]
                        if source != "SafeShell"
                        else sum(f["source"] == source for f in report["findings"])
                        for source in [*sources, "SafeShell"]
                    },
                    false_positive=not dangerous and report["verdict"]["verdict"] == "HIGH RISK",
                    false_negative=dangerous and report["verdict"]["verdict"] != "HIGH RISK",
                    duplicates=report["duplicates_suppressed"],
                    correlations=len(report["correlations"]),
                    execution_relevant=sum(f["execution_relevant"] for f in report["findings"]),
                    duration_seconds=time.monotonic() - started,
                    unavailable_engines=report["verdict"]["unavailable_scanners"],
                )
            )
    labels = [r["expected_high_risk"] for r in rows]
    return dict(
        schema_version="benchmark-1",
        mode="synthetic recorded evidence, not real scanner results",
        samples=rows,
        metrics={
            "SafeShell": metrics(labels, [r["verdict"] == "HIGH RISK" for r in rows]),
            **{
                source: metrics(labels, [r["baselines"][source] for r in rows])
                for source in [*sources, "uncorrelated_scanners"]
            },
        },
    )


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
