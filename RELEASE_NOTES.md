# v0.1.0-alpha.2 — repository trust inspection (experimental prerelease)

Python distribution version: **0.1.0a2**. Git tag: **v0.1.0-alpha.2**.
This alpha is not production-ready and has no independent security audit.
Distribution is through a GitHub prerelease only; **nothing is published to PyPI**.
The original v0.1.0-alpha tag, release and assets are unchanged.

## New repository inspection workflow

```console
safeshell inspect ./unfamiliar-repository
safeshell inspect ./unfamiliar-repository --show-map --verbose
safeshell inspect ./unfamiliar-repository --format json
safeshell map ./unfamiliar-repository
safeshell findings ./unfamiliar-repository
```

Inspection parses a bounded local snapshot without importing target modules,
installing dependencies, running hooks or executing application code. Native
analysis identifies supported manifests and literal process launches, builds a
potential execution graph, correlates security signals and emits evidence-linked
LOW RISK, CAUTION, HIGH RISK or UNKNOWN verdicts. The versioned JSON contract is
`inspection-1`; original command-report schema_version 1 is preserved.

Trivy and OSV-Scanner adapters normalize offline vulnerability, secret and
configuration evidence. Package/version/alias correlation suppresses duplicate
advisories while preserving attribution and secondary evidence. External binaries
and vulnerability databases must be prepared independently; SafeShell never
installs them or uploads source code as part of core inspection.

## Corrections included

- Incomplete coverage remains explicit for unavailable, disabled, timed-out or
  malformed scanner output; `--disable-scanner` is supported.
- Comments, echo arguments and unrelated manual scripts no longer create or
  strengthen automatic invocation chains. Literal npm-run chains are followed.
- Unresolved working directories produce coverage gaps rather than guessed
  sibling script edges. File/line evidence and native finding counts are retained.
- Trivy `pip` and OSV `PyPI` advisories deduplicate with transitive aliases;
  secondary evidence and per-engine counts are preserved.
- Malformed fields and unsupported execution-file encodings are handled
  conservatively; PowerShell UTF-16/BOM and `.PS1` are supported.
- Distribution validation includes nested packages and retains strict rejection
  of unexpected wheel payloads and private or incomplete source archives.
- The release verifier installs both wheel and built sdist in separate clean
  venvs. Source-build dependencies are supplied explicitly from an offline
  wheelhouse; the package still has no runtime Python dependencies.

Existing explain, policy, run, doctor and history behavior and Linux sandbox
restrictions are preserved. Inspection never authorizes or launches execution.

## Install the exact assets

Required: Python 3.11+. These are the three release assets:

- `safeshell_cli-0.1.0a2-py3-none-any.whl`
- `safeshell_cli-0.1.0a2.tar.gz` (built sdist, not GitHub's automatic source archive)
- `SHA256SUMS`

Ubuntu/WSL2 or another POSIX shell, in a new directory:

```sh
mkdir safeshell-alpha2
cd safeshell-alpha2
base=https://github.com/HamzaGhebriche/SafeShell/releases/download/v0.1.0-alpha.2
for asset in safeshell_cli-0.1.0a2-py3-none-any.whl safeshell_cli-0.1.0a2.tar.gz SHA256SUMS; do
  curl --fail --location --output "$asset" "$base/$asset" || exit 1
done
sha256sum --check SHA256SUMS || exit 1
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps ./safeshell_cli-0.1.0a2-py3-none-any.whl
safeshell --version
safeshell inspect . --format json
```

Expected version: **0.1.0a2**. On Windows, create the venv with `python -m venv .venv`
and activate `.venv\Scripts\Activate.ps1`; the wheel supports inspection,
policy and history, while protected execution still requires Linux.

For protected Linux execution, use a normal user with Bubblewrap/libseccomp and
working namespaces. Follow the matching [README](README.md) and
[Ubuntu VM guide](docs/VIRTUALBOX.md); WSL is a different environment. `doctor`
is a setup probe, not proof of containment. Never weaken controls to force it
to pass, and never use `sudo safeshell`.

## Limits that remain visible

- **Static analysis is partial.** Dynamic imports, computed commands/cwd, generated
  code, JSONC and full YAML/control-flow interpretation are outside this alpha.
  False positives and false negatives remain possible. **LOW RISK is no guarantee.**
- **UNKNOWN means analysis is incomplete.** Missing scanners/databases or parser
  gaps remain visible; a strong correlated chain may still warrant HIGH RISK.
- **Inspection CLI exit 0 means a report was generated**, including UNKNOWN/HIGH
  RISK. It does not permit execution. Invalid input/inspection errors use exit 2;
  scanner exit codes are reported separately.
- **External scanners are not inside SafeShell's execution sandbox.** Their
  authority is the host user's; offline flags and tested caches/proxies do not
  enforce an OS network boundary. Scanner process descendants/resource quotas and
  concurrent hostile-writer races remain limits.
- **YARA-X and Scorecard remain feature-gated and unavailable**, not working
  integrations. This can keep ordinary default scans at UNKNOWN.
- The seven-sample benchmark uses synthetic recorded scanner evidence. It is a
  regression harness, **not evidence of general reliability or scanner superiority**.
- **Every file in an execution workspace can be read, changed or deleted**, including
  credentials. Use disposable secret-free copies without concurrent host writers.
  No CPU, memory, process-count or disk quota is enforced. Fixed runtime tools
  exclude arbitrary SDKs/npm/Git/curl; native Windows/macOS execution is refused.

Vulnerable does not mean malicious. Suspicious does not mean malicious. Low
repository posture does not mean malicious. See [inspection limits](docs/INSPECTION.md)
and [sandbox guarantees and limits](docs/SANDBOX.md).

## Validation and provenance

The GitHub prerelease body records the exact tagged commit, successful release
CI, hashes of the CI-built assets and checks after downloading the published
files. Checksums identify bytes; they are not signatures or a security audit.
No old release is replaced and no package-registry upload is performed.

Earlier [review results](docs/INSPECTION_REVIEW.md), including real Trivy 0.76.2
and OSV-Scanner 2.7.1 checks on controlled inputs, are historical evidence. They
are not presented as new tests of scanner versions or a broad real-project benchmark.
