# CI configuration and release provenance

The verified project is [HamzaGhebriche/SafeShell](https://github.com/HamzaGhebriche/SafeShell),
with origin `https://github.com/HamzaGhebriche/SafeShell.git`. It has a dedicated
Git root. The unrelated ancestor repository was never pushed. The repository was
initially private; public visibility and an experimental GitHub prerelease were
subsequently explicitly authorized. Normal commits/pushes preserve history.

## Enforcement and portable jobs

`.github/workflows/ci.yml` uses read-only contents permission and a 15-minute native
Ubuntu 24.04 job. It installs signed distro backend/compiler/venv/AppArmor packages,
loads the scoped profile, and asserts the global userns restriction is still 1.
`SAFESHELL_REQUIRE_BACKEND=1` requires the complete `tests/` directory with **zero
skips** and passing boundary cases. No continue-on-error, mocked backend, container
substitution or host fallback is accepted. Evidence is uploaded even on failure.

Ubuntu's generic AppArmor profile initially denied Bubblewrap loopback setup.
The scoped test-host profile permits trusted namespace assembly and stacks an
enforced capability/userns-denying guest profile on exec. Both profiles must
permit an operation. Replacement transitions correctly failed under NNP; stacking
retains it. The validator requires the exact observed label
`safeshell-bwrap//&safeshell-child (enforce)`. AppArmor permits reachable files;
explicit minimal Bubblewrap mounts remain the filesystem boundary. Disconnected
FD metadata uses a synthetic child prefix. No global security control is disabled.

The portable Ubuntu/Windows/macOS matrix runs lint, format, tests, builds and fresh
offline wheel workflows; fail-fast is disabled. `SAFESHELL_PORTABLE_CI=1` rejects
unexpected skips. Only documented Windows/macOS unavailable-backend boundary
cases and Windows FIFO/hardlink fixture limitations are accepted. Linux portable
tests omit the boundary file because the required native job covers all tests.

## Exact Linux reproduction

Use the normal-user steps in [VIRTUALBOX.md](VIRTUALBOX.md), including scoped
AppArmor installation and reversal. Inside that configured disposable guest:

```sh
python -m pip install pytest ruff==0.17.3 build 'setuptools>=77'
python -m ruff check .
python -m ruff format --check .
sudo -v
SAFESHELL_REQUIRE_BACKEND=1 \
SAFESHELL_EXPECT_APPARMOR_PROFILE='safeshell-bwrap//&safeshell-child' \
python tools/validate_linux.py
python -m build --no-isolation
python tools/smoke_installed.py dist/safeshell_cli-0.1.0a1-py3-none-any.whl --require-backend
python tools/prepare_release_assets.py dist
```

Only temporary fixture provisioning and host prerequisite/policy setup use sudo;
probes and tests remain unprivileged. `doctor` is setup evidence, not a containment
audit. An unavailable backend must refuse execution.

## Distribution and tag checks

The native job builds wheel/sdist from its exact checkout. The installed verifier
uses a fresh venv, no system packages, no-index/no-deps installation and unrelated
cwd. It verifies version/source-import exclusion, explain/script, policy init and
validate, hard denial, run/refusal, limits, history, dummy outside/home/symlink and
socket/environment checks, and delayed-descendant cleanup.

`prepare_release_assets.py` compares wheel/package and sdist source bytes with the
checkout, checks required guides/profile, rejects private/generated archive paths,
and writes SHA256SUMS. `alpha-distributions` uploads those exact three files;
`linux-enforcement-evidence` uploads JUnit/host/inventory/installed receipts.

Release procedure: require all four jobs on the final SHA, inspect artifacts and
history, tag that SHA without rewriting history, build/verify the tag's artifact
receipts, then attach the checked wheel, source archive and checksums to an
**experimental prerelease**. The prerelease body identifies the final SHA, CI run
and asset hashes. GitHub-generated source ZIP/tar links are not the built sdist.
There is no PyPI publishing workflow. Checksums do not imply bit-for-bit
reproducible builds, code signing, independent audit or production readiness.

See [actual results](VALIDATION.md) and [public-readiness review](PUBLIC_REVIEW.md).
Earlier local and private-CI checkpoint evidence is retained and labeled separately.
