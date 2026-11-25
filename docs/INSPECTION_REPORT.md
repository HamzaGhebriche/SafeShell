# Repository trust inspection implementation report

Historical implementation report. The subsequent [pre-merge review](INSPECTION_REVIEW.md)
records corrections, real scanner versions and current validation results.

Implemented on `codex/repository-trust-inspection`. Nothing pushed, merged,
tagged or released. This is an experimental alpha implementation, with live
scanner compatibility still requiring validation before production claims.

## Architecture and reuse

New modules under `safeshell/inspection/`: dataclass evidence/engine/graph models,
bounded inventory and snapshot, literal execution surface analysis, independent
scanner adapters, alias-based dependency deduplication, explainable correlation,
verdict orchestration/rendering and controlled benchmark evaluation.

Reused existing argparse CLI, terminal escaping, packaging and CI matrix. Existing
command lexer/analysis, policies, audit history, Linux Bubblewrap/seccomp backend
and runtime selection are preserved. Inspection never calls execution. Running
still requires an explicit `safeshell run --workspace <copy> -- <command>` and all
existing policy/backend checks. Native Windows/macOS protected execution remains
unsupported; runtime availability and workspace credential exposure remain limits.

## Commands, surfaces, evidence and decisions

New commands: inspect, map, findings. Options: --json/--format json, --verbose,
--show-map, --cache-dir. Local directories only. No dashboard or cloud service.

Surfaces: Node scripts/install hooks; Python build metadata, setup.py and entry
points; shell/Bash/PowerShell/batch/cmd and literal Python/JavaScript script
references; Dockerfile build/runtime; basic Make/Just/Task commands; GitHub workflow
literal lines; VS Code tasks; documented Claude/MCP JSON command fields and agent
instruction-file identification. Dynamic resolution and full YAML/JSONC support
are outside this iteration. Exact support and gaps are in [INSPECTION.md](INSPECTION.md).

Finding categories: vulnerability, secret, misconfiguration, suspicious_file,
repository_posture, execution, sensitive_access, external_download, obfuscation,
persistence, destructive, other. Severity and confidence are separate. Confidence
supports CONFIRMED/HIGH/MEDIUM/LOW/CONTEXTUAL; native literal paths use HIGH at most,
regex behavior MEDIUM. No static finding certifies runtime behavior.

Trivy and OSV v2 adapters parse normalized JSON with provenance, identifiers,
packages/versions/fixes, OSV ranges and bounded subprocess execution. Shared
aliases deduplicate transitively by ecosystem/package/version while retaining
contributing evidence. Secret matches are redacted. Per-engine counts precede
deduplication. All four scanner binaries were absent in this environment; no real
versions detected. Tests use controlled output contracts. YARA-X and Scorecard
are explicitly UNAVAILABLE feature gates, pending reviewed rules/output contracts
and verified repository identity/network policy respectively. They are not claimed
as working live integrations.

SS-CORR-001: a shared potential automatic execution path reaches both downloading
and sensitive/high-impact behavior. SS-CORR-002: an automatic path reaches a
HIGH/CONFIRMED suspicious-file signature. An isolated signature, vulnerability or
poor posture cannot alone create HIGH RISK. Each correlation exports graph/finding
references and explanation. Rule 002 is tested with synthetic adapter evidence.

Verdict precedence: strong correlation → HIGH RISK/HIGH confidence; otherwise
incomplete analysis → UNKNOWN/LOW; findings → CAUTION/MEDIUM; no findings within
declared scope → LOW RISK/MEDIUM. Missing/gated scanners currently cause ordinary
no-chain default scans to abstain as UNKNOWN. Coverage remains visible even when
HIGH RISK takes precedence. No severity sum or maliciousness label is used.

The `inspection-1` JSON contract exports metadata, target, coverage, engine status,
findings, graph, correlations, verdict/recommendation and duplicate count.
[JSON Schema](../schemas/inspection-v1.schema.json) was validated against an
actual generated synthetic example with Draft202012Validator. Legacy command
schema_version 1 is unchanged.

## Validation

Baseline: 97 existing tests; 72 pass and 25 expected skips on Windows. Ruff lint
and formatting passed before changes. No pre-existing coverage threshold or mypy
configuration. The initial default pytest run stalled; successful runs disable
unrelated automatic pytest plugins and use a workspace-local temporary directory.

Final full suite: **119 passed, 25 skipped**; **47 new inspection tests**. Covers
formats, multi-hop paths/cycles/missing files, malformed data, inventory limits,
link/path guards, hostile arguments/output, encoded content, no-execution behavior,
unavailable/timeout/malformed/nonzero scanner output, secret redaction, isolated
and reachable signature evidence, unrelated signals, alias deduplication and all
four verdicts. No unit test requires network or installed engines.

Coverage: **74% overall**, **92% in the new inspection package** (544/590 lines).
Linux runtime/enforcement code is not exercised on Windows; skipped tests are not
evidence of successful Linux enforcement. Baseline coverage was not measured
before implementation and was not configured by the project.

Ruff lint/format pass; scoped mypy over the eight new package modules passes with
`--ignore-missing-imports --follow-imports=silent` (not a strict whole-project typing
claim). Without import-error suppression, mypy also reports the existing
POSIX-only os.getuid reference in audit.py when targeting Windows; runtime guards
already protect that reference. Git diff whitespace check passes.
Wheel and sdist build pass. Fresh installed-wheel smoke passes with a workspace
TEMP/TMP, testing inspect/map plus all existing portable workflows. Initial smoke
failed at the Windows launcher in the redirected sandbox temporary directory;
the workspace-local retry passed. Linux and macOS CI were not run locally.

CI preserves the original portable OS matrix and required Linux boundary job,
adds synthetic benchmark execution, and extends installed-wheel smoke with the
new commands. Real scanners remain outside normal unit-test requirements.

Local validation artifacts (gitignored): validation-results/trust-coverage.json,
trust-build.log, trust-installed-smoke.json, trust-benchmark.json and
trust-example.json. No results are published.

## Benchmark and limitations

Seven synthetic labeled fixtures cover clean, vulnerable, suspicious install,
dangerous synthetic, security research, poor hygiene and dependency-only cases.
Measured regression results: TP=2, FP=0, TN=5, FN=0; precision=1, recall=1,
false-positive rate=0 on **these seven fixtures only**. Scanner evidence is
synthetic recorded evidence. This is not real-engine performance, a representative
mainstream corpus, or evidence of superiority over any scanner.

The harness records expected/actual verdict, source counts, execution relevance,
duplicate suppression, correlations, duration and unavailable engines, and computes
isolated-engine/uncorrelated-evidence baseline metrics. Undefined ratios are null.
The methodology documents independent labeling, immutable commits and disposable
credential-free VM evaluation for future real-project research.

False positives: URLs/path literals in research or test code, dead branches,
script names used as data, broad sensitive-directory patterns, legitimate
download/bootstrap tooling and legitimate automatic security-test hooks.
False negatives: computed paths, imports, generated code, interpreter semantics,
dynamic packaging, encoded payloads outside known patterns, indirect task runners,
YAML multiline blocks, excluded/oversized files and absent scanner databases.

Security limitations: inventory is bounded, skips links/reparse points/hardlinks,
and scanners receive a filtered snapshot with a minimized environment. This does
not enforce isolation against compromised scanners or concurrent hostile writers.
Ancestor replacement races, scanner process descendants and CPU/memory quotas
remain unresolved. Offline flags are not OS-enforced network containment. Use
trusted scanner binaries/caches outside the target and a disposable immutable copy.
JSON evidence can contain sensitive snippets; exports must be handled privately.

LOW RISK does not mean guaranteed safe. Vulnerable does not mean malicious.
Suspicious does not mean malicious. Low repository posture does not mean malicious.

## Observed synthetic example

The local sample contains an install hook referencing setup.ps1, which contains
an example.invalid download and an AWS credential-path reference. It was written
and inspected only; neither the hook nor script was run.

```console
$ safeshell inspect .test-trust-example
SafeShell Trust Check
Verdict: HIGH RISK
Confidence: HIGH
Recommendation: Do not run directly on the host. Review evidence and use a disposable isolated environment.
Why:
- Automatic execution reaches download and sensitive/high-impact behavior
  F00001 [MEDIUM] npm postinstall package.json
  F00002 [HIGH] External download setup.ps1
  F00003 [HIGH] Sensitive access setup.ps1
Findings: 3; duplicates suppressed: 0
SafeShell: complete
Trivy: unavailable (Binary not installed)
OSV-Scanner: unavailable (Binary not installed)
YARA-X: unavailable (Feature gated: requires reviewed rules and validated JSON contract)
Scorecard: unavailable (Feature gated: local target has no verified GitHub identity; network disabled)
```

```console
$ safeshell map .test-trust-example
SafeShell execution map (potential literal paths)
package.json: npm postinstall --triggers--> package.json: powershell setup.ps1
package.json: package.json --invokes--> package.json: powershell setup.ps1
setup.ps1: setup.ps1 --downloads--> setup.ps1: external download
setup.ps1: setup.ps1 --reads--> setup.ps1: sensitive access
package.json: powershell setup.ps1 --invokes--> setup.ps1: setup.ps1
```

## Recommended next five GitHub issues

1. Pin and validate real Trivy/OSV versions and offline database layouts across
   supported OSes; add opt-in integration contract fixtures and compatibility CI.
2. Introduce OS-enforced containment for scanner subprocesses, process-tree
   deadlines and resource quotas; eliminate hostile-writer snapshot races.
3. Add reviewed YARA-X rule bundles with confidence calibration and verified
   JSON normalization; retain research context and isolated-match caution.
4. Extend semantic invocation resolution, build backend edges and safe YAML/JSONC
   parsers; reduce literal-string false positives with provenance-aware edges.
5. Build an independently labeled real-project benchmark with database/commit
   versions, UNKNOWN/abstention analysis and optional verified Scorecard metadata.
