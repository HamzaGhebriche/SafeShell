"""Nested package payloads remain subject to strict distribution validation."""

import io
import sys
import tarfile
import zipfile

import pytest

from tools import prepare_release_assets


@pytest.mark.parametrize(
    "scenario", ["valid", "unexpected-wheel-file", "missing-module", "private-source-file"]
)
def test_nested_package_distribution_validation(tmp_path, monkeypatch, scenario):
    checkout = tmp_path / "checkout"
    destination = tmp_path / "dist"
    destination.mkdir()
    modules = [
        "safeshell/__init__.py",
        "safeshell/inspection/__init__.py",
        "safeshell/inspection/engine.py",
    ]
    required = [
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "pyproject.toml",
        "docs/VIRTUALBOX.md",
        "docs/FRIEND_TESTING.md",
        ".github/apparmor/safeshell-bwrap",
        "tests/conftest.py",
    ]
    for name in [*modules, *required]:
        path = checkout / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("controlled fixture: " + name, encoding="utf-8")
    version = prepare_release_assets.VERSION
    with zipfile.ZipFile(destination / f"safeshell_cli-{version}-py3-none-any.whl", "w") as archive:
        for name in modules:
            archive.write(checkout / name, name)
        archive.writestr(f"safeshell_cli-{version}.dist-info/METADATA", "fixture metadata")
        if scenario == "unexpected-wheel-file":
            archive.writestr("safeshell/inspection/cache.db", "must not ship")
    prefix = f"safeshell_cli-{version}/"
    with tarfile.open(destination / f"safeshell_cli-{version}.tar.gz", "w:gz") as archive:
        for name in [*modules, *required]:
            if scenario == "missing-module" and name == modules[-1]:
                continue
            archive.add(checkout / name, arcname=prefix + name)
        if scenario == "private-source-file":
            data = b"private fixture"
            member = tarfile.TarInfo(prefix + "validation-results/cache.json")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    monkeypatch.setattr(prepare_release_assets, "ROOT", checkout)
    monkeypatch.setattr(sys, "argv", ["prepare_release_assets", str(destination)])
    if scenario == "valid":
        prepare_release_assets.main()
        assert len((destination / "SHA256SUMS").read_text().splitlines()) == 2
    else:
        expected = {
            "unexpected-wheel-file": "Unexpected wheel payload",
            "missing-module": "Archive/source mismatch",
            "private-source-file": "Unsafe or private source-archive path",
        }[scenario]
        with pytest.raises(ValueError, match=expected):
            prepare_release_assets.main()
        assert not (destination / "SHA256SUMS").exists()
