"""Check distribution contents against this checkout and write release SHA256SUMS."""

import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0a1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()
    wheel = args.dist / f"safeshell_cli-{VERSION}-py3-none-any.whl"
    source = args.dist / f"safeshell_cli-{VERSION}.tar.gz"
    expected = {
        p.relative_to(ROOT).as_posix(): p.read_bytes() for p in (ROOT / "safeshell").glob("*.py")
    }
    metadata = f"safeshell_cli-{VERSION}.dist-info/"
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate wheel entries")
        if {n for n in names if not n.startswith(metadata)} != set(expected):
            raise ValueError("Unexpected wheel payload")
        for name, data in expected.items():
            if archive.read(name) != data:
                raise ValueError(f"Wheel/source mismatch: {name}")
    prefix = f"safeshell_cli-{VERSION}/"
    forbidden = {
        ".git",
        ".build-tmp",
        "validation-results",
        "dist",
        "release-assets",
        "__pycache__",
        ".venv",
    }
    with tarfile.open(source) as archive:
        files = {}
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or forbidden.intersection(path.parts):
                raise ValueError("Unsafe or private source-archive path")
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError("Unexpected source-archive object")
            if member.isfile():
                if not member.name.startswith(prefix) or member.name in files:
                    raise ValueError("Unexpected or duplicate source-archive entry")
                files[member.name] = archive.extractfile(member).read()
        for name, data in expected.items():
            if files.get(prefix + name) != data:
                raise ValueError(f"Archive/source mismatch: {name}")
        for name in (
            "README.md",
            "LICENSE",
            "SECURITY.md",
            "pyproject.toml",
            "docs/VIRTUALBOX.md",
            "docs/FRIEND_TESTING.md",
            ".github/apparmor/safeshell-bwrap",
            "tests/conftest.py",
        ):
            if files.get(prefix + name) != (ROOT / name).read_bytes():
                raise ValueError(f"Required release file missing or different: {name}")
    checksums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (wheel, source)}
    (args.dist / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in checksums.items()), encoding="ascii"
    )
    print(
        json.dumps(
            {"version": VERSION, "sha256": checksums, "payload_matches_checkout": True}, indent=2
        )
    )


if __name__ == "__main__":
    main()
