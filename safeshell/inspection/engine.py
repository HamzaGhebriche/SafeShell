"""Shared orchestration for terminal, JSON and benchmark consumers."""

import shutil
import tempfile
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from ..audit import safe
from .adapters import Adapter, default_adapters
from .decision import decide, deduplicate
from .inventory import inventory, snapshot
from .models import EngineResult
from .surfaces import analyze


def inspect_repository(
    target: Path,
    adapters: list[Adapter] | None = None,
    cache: Path | None = None,
    disabled: list[str] | None = None,
) -> dict:
    started = time.monotonic()
    started_at = datetime.now(UTC).isoformat()
    inv = inventory(target)
    if cache is not None:
        cache = cache.resolve()
        if cache.is_relative_to(inv.root):
            raise ValueError("Scanner cache must be trusted and outside the inspected repository")
    findings, graph, gaps = analyze(inv)
    gaps = inv.gaps + gaps
    engines = [
        EngineResult(
            "SafeShell", "PARTIAL" if gaps else "COMPLETE", findings.copy(), reason="; ".join(gaps)
        )
    ]
    selected = default_adapters() if adapters is None else adapters
    names = {"trivy": "Trivy", "osv": "OSV-Scanner", "yara-x": "YARA-X", "scorecard": "Scorecard"}
    if any(name not in names for name in (disabled or [])):
        raise ValueError("Unknown disabled scanner")
    disabled_sources = {names[name] for name in (disabled or [])}
    for source in names.values():
        if source not in {adapter.source for adapter in selected}:
            engines.append(
                EngineResult(source, "DISABLED", reason="Not selected for this analysis")
            )
    with tempfile.TemporaryDirectory(prefix="safeshell-inspect-") as directory:
        work = Path(directory)
        tree, state = work / "repository", cache or work / "cache"
        tree.mkdir()
        state.mkdir(parents=True, exist_ok=True)
        (state / "empty-ignore").write_text("", encoding="utf-8")
        snapshot(inv, tree)
        for adapter in selected:
            try:
                binary = getattr(adapter, "binary", None)
                executable = shutil.which(binary) if binary else None
                if adapter.source in disabled_sources:
                    result = EngineResult(adapter.source, "DISABLED", reason="Explicitly disabled")
                elif executable and Path(executable).resolve().is_relative_to(inv.root):
                    result = EngineResult(
                        adapter.source,
                        "UNAVAILABLE",
                        reason="Scanner binary is inside inspected repository",
                    )
                else:
                    result = adapter.scan(tree, state)
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                result = EngineResult(adapter.source, "PARTIAL", reason=type(exc).__name__)
            for finding in result.findings:
                if finding.file:
                    raw = finding.file.replace("\\", "/")
                    prefix = tree.as_posix() + "/"
                    raw = raw.removeprefix(prefix)
                    finding.file = raw
                    node = next(
                        (n["id"] for n in graph.nodes if n["kind"] == "file" and n["file"] == raw),
                        None,
                    )
                    if node:
                        finding.metadata["node"] = node
            findings.extend(result.findings)
            engines.append(result)
    reachable = set()
    for finding in findings:
        if (
            finding.source == "SafeShell"
            and finding.category == "execution"
            and finding.execution_relevant
        ):
            reachable.update(graph.reachable(finding.metadata["node"]))
    for finding in findings:
        if finding.source != "SafeShell":
            finding.execution_relevant = finding.metadata.get("node") in reachable
    statuses = [
        {
            "source": e.source,
            "status": e.status,
            "reason": e.reason,
            "version": e.version,
            "exit_code": e.exit_code,
            "finding_count": len(e.findings),
            "high_severity_count": sum(f.severity in {"HIGH", "CRITICAL"} for f in e.findings),
        }
        for e in engines
    ]
    findings, duplicates = deduplicate(findings)
    incomplete = bool(gaps) or any(e.status != "COMPLETE" for e in engines)
    correlations, verdict = decide(findings, graph, incomplete)
    coverage = {
        "complete": not incomplete,
        "files": len(inv.files),
        "entries": inv.entries,
        "gaps": gaps,
        "excluded": inv.excluded,
        "scope": "Bounded snapshot; literal static execution surfaces only",
    }
    verdict["analysis_coverage"] = coverage
    verdict["unavailable_scanners"] = [e.source for e in engines if e.status == "UNAVAILABLE"]
    verdict["disabled_scanners"] = [e.source for e in engines if e.status == "DISABLED"]
    return {
        "schema_version": "inspection-1",
        "scan": {
            "started_at": started_at,
            "duration_seconds": round(time.monotonic() - started, 6),
            "offline": True,
        },
        "target": {"kind": "local_directory", "path": str(inv.root)},
        "coverage": coverage,
        "engines": statuses,
        "findings": [asdict(f) for f in findings],
        "execution_graph": asdict(graph),
        "correlations": correlations,
        "verdict": verdict,
        "duplicates_suppressed": duplicates,
        "limitations": [
            "Static evidence is not proof of malicious intent.",
            "Literal references may be data or unreachable branches.",
            "Use a disposable immutable copy; concurrent hostile writers are unsupported.",
            "Dynamic imports, expressions and generated code are not resolved.",
        ],
    }


def render_map(report: dict) -> str:
    graph = report["execution_graph"]
    labels = {n["id"]: f"{n['file'] or ''}: {n['label']}" for n in graph["nodes"]}
    lines = ["SafeShell execution map (potential literal paths)"]
    lines.extend(
        f"{labels[e['source']]} --{e['relation']}--> {labels[e['target']]}" for e in graph["edges"]
    )
    return "\n".join(
        safe(line)
        for line in (lines if graph["edges"] else lines + ["No execution edges identified."])
    )


def render(report: dict, verbose=False) -> str:
    verdict = report["verdict"]
    lines = [
        "SafeShell Trust Check",
        f"Verdict: {verdict['verdict']}",
        f"Confidence: {verdict['confidence']}",
        "Recommendation: " + verdict["recommended_action"],
        "Why:",
    ]
    lines.extend("- " + reason for reason in verdict["primary_reasons"])
    evidence_ids = set(verdict["evidence_references"])
    for finding in [f for f in report["findings"] if f["finding_id"] in evidence_ids][:6]:
        location = f" {finding['file']}" if finding["file"] else ""
        lines.append(
            f"  {finding['finding_id']} [{finding['severity']}] {finding['title']}{location}"
        )
    lines.append(
        f"Findings: {len(report['findings'])}; duplicates suppressed: {report['duplicates_suppressed']}"
    )
    lines.extend(
        f"{e['source']}: {e['status'].lower()}"
        + (
            f" ({e['reason'][:180]}{'...' if len(e['reason']) > 180 else ''})"
            if e["reason"]
            else ""
        )
        for e in report["engines"]
    )
    if verbose:
        for finding in report["findings"]:
            lines.append(
                f"{finding['finding_id']} [{finding['source']}] {finding['category']} "
                f"{finding['file']}:{finding['line']} {finding['title']} "
                f"confidence={finding['confidence']} evidence={finding['evidence']}"
            )
    lines.append("Use --format json for all evidence; --show-map for potential execution paths.")
    return "\n".join(safe(line) for line in lines)
