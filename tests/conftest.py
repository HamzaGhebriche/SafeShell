"""A required enforcement run must never succeed by skipping tests."""

import os

import pytest

_skipped = False
_enforcement_passed = 0


def pytest_sessionstart(session):
    global _skipped, _enforcement_passed
    _skipped, _enforcement_passed = False, 0


def pytest_runtest_logreport(report):
    global _skipped, _enforcement_passed
    _skipped |= report.skipped
    if report.when == "call" and report.passed and "test_linux_boundary.py::" in report.nodeid:
        _enforcement_passed += 1


def pytest_collectreport(report):
    global _skipped
    _skipped |= report.skipped


def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("SAFESHELL_REQUIRE_BACKEND") != "1":
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if _skipped or not _enforcement_passed:
        if reporter:
            reporter.write_sep(
                "!", "Required enforcement run skipped tests or ran no passing boundary tests"
            )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(scope="session")
def enforcement():
    from safeshell import backend

    capability = backend.discover()
    if not capability.available:
        if os.environ.get("SAFESHELL_REQUIRE_BACKEND") == "1":
            pytest.fail(capability.reason)
        pytest.skip(capability.reason)
