# Repository trust inspection (experimental alpha)

SafeShell helps developers evaluate untrusted repositories before running them
and provides containment when execution is necessary. Hide complexity by default,
never hide evidence. Inspection parses files as data; it never installs target
dependencies, imports target modules, runs hooks, sources scripts or invokes Make.

```console
safeshell inspect ./unfamiliar-repo
safeshell inspect ./unfamiliar-repo --verbose --show-map
safeshell inspect ./unfamiliar-repo --format json
safeshell findings ./unfamiliar-repo
safeshell map ./unfamiliar-repo
safeshell inspect ./unfamiliar-repo --disable-scanner trivy
```

All three commands inspect anew; no hidden persistent report cache. Exit 0 means
report generated, including HIGH RISK/UNKNOWN; exit 2 means input/inspection error.
Do not use exit 0 as execution approval. JSON is the complete expert interface.
Text output escapes terminal controls. Reports are not uploaded or persisted.
JSON can contain source snippets and sensitive paths; handle exports privately.
Trivy matched secret contents are deliberately redacted rather than exported.

## Supported surfaces and confidence

- Node package.json scripts; preinstall/install/postinstall/prepare are potential
  automatic triggers. Other scripts are manual. Nested packages are inventoried,
  but workspace installation relationships are not resolved.
- Python pyproject build-system and project.scripts, setup.py and setup.cfg
  entry points. Custom build backends produce a coverage gap; module entry-point
  resolution and dynamic packaging are not implemented.
- Shell/Bash, PowerShell, batch/cmd, Python and JavaScript literal file references
  in recognized process-launch contexts and behavioral patterns. Shell interpreter
  commands, literal Node spawn/exec calls and Python subprocess/os.system arguments
  are recognized. Bare filenames, echo arguments and comments do not create
  invocation edges. Literal `npm run` chains are followed, including cycles.
  These are potential paths, not proven interpreter or control-flow semantics.
  Explicit/dynamic working-directory changes and nested-package child-process cwd
  are not resolved; gaps are reported instead of guessing a sibling script path.
  UTF-8/BOM text and PowerShell UTF-16 with BOM are supported, including `.PS1`.
  Unsupported encoding or NUL content in recognized execution files is a coverage gap.
- Dockerfile RUN/CMD/ENTRYPOINT (potential build/runtime triggers); Makefile and
  basic Justfile/Taskfile command lines (manual).
- GitHub workflows: literal run/uses/permissions lines only. YAML is not evaluated;
  multiline blocks, expressions and aliases are not resolved and coverage is PARTIAL.
- Strict JSON VS Code tasks, including folderOpen; JSONC unsupported.
- .claude/settings.json, .claude/settings.local.json, .cursor/mcp.json,
  .vscode/mcp.json and .mcp.json literal command keys are conditional agent/server
  surfaces. AGENTS.md and CLAUDE.md are identified, not interpreted as instructions.

Signals: external URLs/download commands, sensitive credential/config paths,
startup/cron/service references, destructive commands, encoded PowerShell and
base64-to-shell patterns. A URL or a path reference is not evidence of intent.
Comments, examples, security research and dead branches can trigger findings.
Only relationships within one reachable trigger contribute to strong correlation.

Severity describes potential impact. Confidence describes evidentiary certainty:
CONFIRMED (reserved for directly established facts), HIGH, MEDIUM, LOW,
CONTEXTUAL (posture/context). Static literal invocation evidence is HIGH at most;
behavioral regex matches are MEDIUM. Actual exploitability remains unknown.

## Engines, installation and privacy

SafeShell never installs scanners. Install reviewed binaries independently from
the projects' official distributions. Detected versions appear in JSON. Trivy and
OSV use bounded JSON output, explicit 60-second scan/5-second version deadlines,
no shell, closed stdin, isolated HOME/config/temp and no inherited credentials.
Each output pipe is limited to 4 MiB (version: 8 KiB). Nonzero/error/timeout/invalid
JSON becomes PARTIAL; missing binaries become UNAVAILABLE. OSV exit 1 with valid
vulnerability evidence is accepted. Stderr content is not exported because it
may contain credentials; error class/exit and engine attribution are retained.
JSON engine statuses include the scanner exit_code separately from the CLI exit.
`--disable-scanner trivy|osv|yara-x|scorecard` is repeatable and reports DISABLED.
Disabled or programmatically unselected engines keep coverage incomplete. Even
an empty native-only scan cannot return LOW RISK. Native finding counts are included.

Trivy uses filesystem vulnerability, secret and misconfiguration scanners with
offline resolution, skipped DB/check/version updates and disabled telemetry.
OSV uses v2 `scan source --offline --format json --recursive --no-ignore`; target
.gitignore files cannot suppress dependency coverage. Unsupported versions
and missing offline databases produce PARTIAL, never a clean bill of health.
The pre-merge review exercised real Windows Trivy 0.76.2 and OSV-Scanner 2.7.1
binaries with verified release checksums, populated/empty caches and controlled
dependencies. See [measured review results](INSPECTION_REVIEW.md). Other versions
and OS-specific scanner binaries remain unverified. On Windows the recursive OSV
walker may need access to ancestor directories; restricted environments can return
exit 128. SafeShell reports PARTIAL, not an empty successful analysis.

Provide a trusted cache with `--cache-dir /trusted/cache`: `trivy/` contains the
Trivy cache and `osv/osv-scalibr/<ecosystem>/all.zip` the OSV databases. Prepare and
update databases separately, with explicit network access, per upstream docs:
[Trivy filesystem options](https://trivy.dev/docs/dev/guide/references/configuration/cli/trivy_filesystem/)
and [OSV offline mode](https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md).
Without this option, an empty disposable cache is used. Core inspection makes no
network requests; scanner offline flags are application settings, not an OS network
boundary. For enforced offline scanning run SafeShell itself inside a suitably
configured isolated environment. Source is not sent to external APIs by SafeShell.

YARA-X is feature-gated pending a reviewed local ruleset and validated output
contract. Scorecard is feature-gated for local targets: no inferred GitHub identity,
credential access or metadata network requests. This is explicit UNAVAILABLE
coverage, not an empty successful scan. Future adapters implement the shared
`scan(target, cache) -> EngineResult` protocol without changing the core model.

Scanners receive a bounded snapshot without .git, environments, node_modules,
symlinks, hardlinks, special files or target-controlled scanner config. Inventory
limits: 10,000 entries, depth 32, 1 MiB/file, 32 MiB total. Native analysis additionally
limits 2,000 text files, 128 KiB/2,000 lines per text file, 1,000 commands, 4,000
findings and 100 literal references per command/file. Limit hits are coverage gaps.
Excluded dependency directories are listed; resolved dependency coverage requires
supported manifests/lockfiles. Unknown formats and generated code remain outside
the declared scope even when coverage says complete.

Use a disposable immutable copy with no concurrent hostile writers. Final-file
O_NOFOLLOW on POSIX, descriptor metadata checks and Windows reparse checks reduce
link attacks; ancestor replacement races and scanner vulnerabilities are not an
enforced sandbox boundary. Trusted cache and scanner binaries must not be located
inside the target repository. Scanners run with the user's OS authority and can
access other host files if compromised. There is no CPU/memory/process quota for
scanner subprocesses. The timeout bounds the direct scanner, not arbitrary child
trees from a compromised scanner.

## Correlation and verdicts

Dependency findings deduplicate by package, ecosystem, installed version and shared
CVE/GHSA/OSV aliases. All contributing tool evidence remains in additional_evidence;
per-engine counts precede deduplication. A vulnerability does not establish an
automatic execution path. Scorecard posture is contextual and cannot create HIGH RISK.

- SS-CORR-001: one potential automatic trigger reaches an external download and
  sensitive access, destructive behavior, persistence or obfuscation.
- SS-CORR-002: potential automatic execution reaches a HIGH/CONFIRMED suspicious
  file signature. Reserved for enabled reviewed adapters; isolated signatures
  cannot invoke this rule.

HIGH RISK takes precedence when a strong rule matches, even if coverage is incomplete.
Otherwise incomplete required analysis yields UNKNOWN, findings yield CAUTION,
and no findings yields LOW RISK within the declared static scope. Feature-gated
engines currently mean ordinary no-chain default scans yield UNKNOWN. Reports
contain confidence, primary reasons, recommendation, coverage, unavailable engines,
finding IDs, graph and correlation evidence references. No severity sum is used.

**LOW RISK does not mean guaranteed safe. Vulnerable does not mean malicious.
Suspicious does not mean malicious. Low repository posture does not mean malicious.**

## Execution remains explicit

Inspection never invokes the sandbox or authorizes execution. Existing syntax:

```console
safeshell doctor
safeshell run --workspace ./disposable-copy -- npm test
```

Review the inspection first, then explicitly submit the exact command. Existing
policies, hard denials, confirmations, workspace checks and Linux-only fail-closed
Bubblewrap backend still apply. There is no new `--sandbox` switch or second
sandbox. The existing minimum runtime may not provide npm/Python dependencies;
no automatic runtime expansion is performed. Workspace secrets remain exposed to
executed code; remove them. See [sandbox guarantees and limitations](SANDBOX.md).

## JSON contract

`schema_version: "inspection-1"` is separate from legacy command schema_version 1.
Top-level keys: scan (time/duration/offline), target (kind/path), coverage,
engines (status/version/reason/counts), findings, execution_graph, correlations,
verdict, duplicates_suppressed and limitations. Findings contain finding_id,
source/category/severity/confidence, title/description, file/line, evidence,
identifiers, package/installed_version/fixed_version, execution_relevant and
metadata. Categories include vulnerability, secret, misconfiguration,
suspicious_file, repository_posture, execution, sensitive_access, external_download,
obfuscation, persistence, destructive and other. Graph nodes have id/kind/label/file;
edges have source/target/relation. Reachability is potential, never a runtime fact.
Future incompatible changes require a new schema version.

## Evaluation

```console
python -m safeshell.inspection.benchmark > benchmark.json
```

Seven controlled fixtures cover clean synthetic code, vulnerable training code,
suspicious installation, synthetic dangerous behavior, security research,
poor posture and dependency-only findings. Files are written as data, never run.
Scanner evidence is explicitly synthetic recorded evidence, not measured output
from installed engines. No claim of superiority or real-world accuracy is warranted.

The report records expected/actual verdicts, high-risk ground truth, raw per-engine
counts, native counts, duplicate suppression, correlations, execution relevance,
duration, unavailable engines and FP/FN. Metrics: TP/FP/TN/FN, precision, recall and
false-positive rate; undefined ratios are null. Baselines use each engine's HIGH/
CRITICAL evidence as a deliberately simple high-risk threshold, plus combined
uncorrelated scanner evidence. They do not represent upstream maliciousness verdicts.

For real evaluation: independently label exact immutable commits of mainstream
projects, intentionally vulnerable training repositories and legitimate security
tools; record label rationale, licenses, engine/database versions and supported
coverage. Run only static inspection in a disposable network-restricted VM without
credentials. Never fetch or execute real malware in ordinary CI. Keep evaluation
artifacts private where evidence includes secrets; manually review abstentions
(UNKNOWN), false positives and false negatives. The synthetic harness is a
regression framework, not a representative benchmark dataset.
