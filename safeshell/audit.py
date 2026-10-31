"""Private metadata records. Never persist child output or environment values."""

import json
import os
import re
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path


def safe(text: str) -> str:
    return "".join(
        c
        if c.isprintable() and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        else f"\\u{ord(c):04x}"
        for c in text
    )


def redact(argv: list[str]) -> str:
    # Deliberately lossy: no argument values, paths, inline scripts or URLs are retained.
    if not argv:
        return "[empty]"
    executable = Path(argv[0]).name
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", executable):
        executable = "[command]"
    return f"{executable} [{max(0, len(argv) - 1)} arguments omitted]"


def storage() -> Path:
    base = Path(os.environ.get("SAFESHELL_STATE_DIR", str(Path.home() / ".local/state/safeshell")))
    if base.is_symlink():
        raise ValueError("History directory cannot be a symlink")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        info = base.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("History directory must be owned by you with mode 0700")
    return base


def new_record(argv: list[str], report: dict, decision: dict, backend: dict, audit: str) -> dict:
    return {
        "schema_version": 1,
        "id": str(uuid.uuid4()),
        "started_at": datetime.now(UTC).isoformat(),
        "ended_at": None,
        "command": redact(argv) if audit == "redacted" else "[metadata only]",
        "risk": report["risk"],
        "findings": [
            {"id": rule, "severity": severity}
            for rule, severity in sorted({(f["id"], f["severity"]) for f in report["findings"]})
        ],
        "decision": decision,
        "backend": backend,
        "status": "prepared",
        "exit_code": None,
    }


def save(record: dict) -> None:
    root = storage()
    target = root / (identifier(record["id"]) + ".json")
    temp = root / (str(uuid.uuid4()) + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)


def identifier(value: str) -> str:
    parsed = str(uuid.UUID(value))
    if parsed != value:
        raise ValueError("Session ID must be a canonical UUID")
    return parsed


def read(value: str) -> dict:
    path = storage() / (identifier(value) + ".json")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 131072:
        raise ValueError("Invalid history record")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        raise ValueError("Invalid history schema")
    return record


def records() -> list[dict]:
    result = []
    for path in storage().glob("*.json"):
        try:
            result.append(read(path.stem))
        except (ValueError, OSError):
            continue
    return sorted(result, key=lambda r: str(r.get("started_at", "")), reverse=True)


def delete(value: str) -> None:
    (storage() / (identifier(value) + ".json")).unlink()
