"""A required enforcement run must never succeed by skipping tests."""

import os
import sys

import pytest

_skipped = False
_enforcement_passed = 0
_unexpected_portable_skip = False


def pytest_sessionstart(session):
    global _skipped, _enforcement_passed, _unexpected_portable_skip
    _skipped, _enforcement_passed = False, 0
    _unexpected_portable_skip = False


def pytest_runtest_logreport(report):
    global _skipped, _enforcement_passed, _unexpected_portable_skip
    _skipped |= report.skipped
    if report.skipped:
        node = report.nodeid.replace("\\", "/")
        reason = str(report.longrepr)
        expected = (
            sys.platform in ("win32", "darwin")
            and node.startswith("tests/test_linux_boundary.py::")
            and "Protected execution requires Linux, bubblewrap and libseccomp" in reason
        ) or (
            sys.platform == "win32"
            and (
                (
                    node == "tests/test_core.py::test_nonregular_history_record_cannot_block"
                    and "POSIX FIFO fixture unsupported on Windows" in reason
                )
                or (
                    node == "tests/test_core.py::test_workspace_hardlink_rejected"
                    and "Host cannot create test hardlinks:" in reason
                )
            )
        )
        _unexpected_portable_skip |= not expected
    if report.when == "call" and report.passed and "test_linux_boundary.py::" in report.nodeid:
        _enforcement_passed += 1


def pytest_collectreport(report):
    global _skipped, _unexpected_portable_skip
    _skipped |= report.skipped
    _unexpected_portable_skip |= report.skipped


def pytest_sessionfinish(session, exitstatus):
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if os.environ.get("SAFESHELL_PORTABLE_CI") == "1" and _unexpected_portable_skip:
        if reporter:
            reporter.write_sep("!", "Portable CI encountered an unexpected skip")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
    if os.environ.get("SAFESHELL_REQUIRE_BACKEND") != "1":
        return
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
