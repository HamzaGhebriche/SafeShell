# Contributing

Use Python 3.11+. Install development tools with
`python -m pip install pytest ruff==0.17.3 build 'setuptools>=77'`.
Run `python -m ruff format --check .`, `python -m ruff check .`,
`python -m pytest -ra --ignore=tests/test_linux_boundary.py`, and `python -m build --no-isolation`.
For real Linux enforcement checks, use `python3 tools/validate_linux.py` on a disposable VM
with bubblewrap, libseccomp2, build-essential (compiler plus C headers), pytest and passwordless sudo. The runner provisions/removes
temporary root-owned dummy controls. Root-default WSL can use the root-only harness option
`--as-user nobody`; every probe/test subprocess still runs without root privileges.

The runner sets SAFESHELL_REQUIRE_BACKEND=1 and the session gate fails on any skip or missing
passing boundary tests. See [validation](docs/VALIDATION.md) for the actual tested configuration.

Security-sensitive changes need tests that distinguish predictions from effective enforcement.
Use temporary workspaces and dummy secrets only. Linux integration tests must exercise the real
backend. Set SAFESHELL_REQUIRE_BACKEND=1 on a supported test host; otherwise an unavailable
backend produces explicit skips. Never convert backend failures into a host fallback or weaken
policies to make tests pass. Do not add raw commands, environment values or child output to audit.

Keep modules small and policy evaluation pure. Document new capabilities and unsupported cases.
Changing risk rules must not change sandbox restrictions. Follow the security reporting guidance
for discovered bypasses instead of adding live exploit data to ordinary issues.


Use [VIRTUALBOX.md](docs/VIRTUALBOX.md) for exact Ubuntu scoped AppArmor setup and
reversal. Never globally disable host controls. Native CI requires zero skips;
portable CI uses SAFESHELL_PORTABLE_CI=1 to reject unexpected skips. Tests may
explicitly skip only unavailable Windows/macOS boundary support and documented
Windows fixture limitations. Add regression coverage for any gate changes.

Before a GitHub prerelease, run `python tools/prepare_release_assets.py dist` after
building and installed-wheel checks. Tag the tested commit and attach the CI-built
wheel/sdist/SHA256SUMS; do not silently rebuild different bytes after checks or
publish to a registry. Public issues use the bug/documentation templates; keep
suspected boundary bypass details in the private reporting channel.
