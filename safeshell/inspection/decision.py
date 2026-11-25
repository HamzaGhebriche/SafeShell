"""Explainable relationship rules; scanner severity counts never determine the verdict."""

from .models import Finding, Graph


def ecosystem(finding: Finding) -> str:
    value = (finding.metadata.get("ecosystem") or "").lower()
    return {
        "pip": "pypi",
        "python-pkg": "pypi",
        "node-pkg": "npm",
        "gobinary": "go",
        "gomod": "go",
    }.get(value, value)


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    output: list[Finding] = []
    aliases: dict[tuple, int] = {}
    parents = list(range(len(findings)))

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for index, finding in enumerate(findings):
        if finding.category == "vulnerability" and finding.package and finding.installed_version:
            for identifier in finding.identifiers:
                key = (finding.package, finding.installed_version, ecosystem(finding), identifier)
                if key in aliases:
                    left, right = root(index), root(aliases[key])
                    parents[max(left, right)] = min(left, right)
                aliases[key] = index
    groups: dict[int, Finding] = {}
    for index, finding in enumerate(findings):
        group = root(index)
        if group in groups:
            match = groups[group]
            match.identifiers = sorted(set(match.identifiers + finding.identifiers))
            match.metadata.setdefault("additional_evidence", []).append(
                {
                    "source": finding.source,
                    "file": finding.file,
                    "line": finding.line,
                    "identifiers": finding.identifiers.copy(),
                    "evidence": finding.evidence,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "fixed_version": finding.fixed_version,
                    "execution_relevant": finding.execution_relevant,
                    "metadata": finding.metadata.copy(),
                }
            )
        else:
            output.append(finding)
            groups[group] = finding
    for number, finding in enumerate(output, 1):
        finding.finding_id = f"F{number:05}"
    return output, len(findings) - len(output)


def decide(findings: list[Finding], graph: Graph, incomplete: bool) -> tuple[list[dict], dict]:
    correlations = []
    # Correlate only evidence reachable from the SAME trigger, never unrelated files.
    for trigger in (n for n in graph.nodes if n["kind"] == "trigger" and n.get("automatic")):
        reached = graph.reachable(trigger["id"])
        related = [f for f in findings if f.metadata.get("node") in reached]
        automatic = [f for f in related if f.category == "execution" and f.execution_relevant]
        downloads = [f for f in related if f.category == "external_download"]
        sensitive = [
            f
            for f in related
            if f.category in {"sensitive_access", "destructive", "persistence", "obfuscation"}
        ]
        signatures = [
            f
            for f in related
            if f.category == "suspicious_file" and f.confidence in {"HIGH", "CONFIRMED"}
        ]
        rule = None
        if automatic and downloads and sensitive:
            rule = (
                "SS-CORR-001",
                "Automatic execution reaches download and sensitive/high-impact behavior",
                automatic + downloads + sensitive,
            )
        elif automatic and signatures:
            rule = (
                "SS-CORR-002",
                "Automatic execution reaches a high-confidence suspicious pattern",
                automatic + signatures,
            )
        if rule:
            identifier, reason, evidence = rule
            correlations.append(
                {
                    "rule": identifier,
                    "explanation": reason,
                    "trigger": trigger["id"],
                    "evidence": sorted({f.finding_id for f in evidence}),
                }
            )
    if correlations:
        verdict, confidence = "HIGH RISK", "HIGH"
        reasons = [c["explanation"] for c in correlations]
        action = "Do not run directly on the host. Review evidence and use a disposable isolated environment."
    elif incomplete:
        verdict, confidence = "UNKNOWN", "LOW"
        reasons = [
            "Analysis coverage is incomplete; available evidence does not establish a high-risk chain."
        ]
        action = "Review coverage gaps and findings before deciding whether to execute."
    elif findings:
        verdict, confidence = "CAUTION", "MEDIUM"
        reasons = ["Findings exist without a strong correlated automatic execution chain."]
        action = "Review findings and execution surfaces before running."
    else:
        verdict, confidence = "LOW RISK", "MEDIUM"
        reasons = [
            "No strong risky execution evidence detected. LOW RISK does not mean guaranteed safe."
        ]
        action = "Review limitations and use containment for unfamiliar code."
    return correlations, {
        "verdict": verdict,
        "confidence": confidence,
        "primary_reasons": reasons,
        "recommended_action": action,
        "evidence_references": sorted({f for c in correlations for f in c["evidence"]})
        if correlations
        else [f.finding_id for f in findings],
    }
