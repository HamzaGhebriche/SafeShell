"""Bounded inventory; reparse points, links and special files are never followed."""

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

EXCLUDED = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
CONFIG = {"trivy.yaml", "trivy.yml", "trivy-secret.yaml", "osv-scanner.toml", ".trivyignore"}


@dataclass
class Inventory:
    root: Path
    files: dict[str, bytes] = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    entries: int = 0


def inventory(target: Path, max_entries=10000, max_file=1048576, max_total=33554432) -> Inventory:
    if target.is_symlink() or getattr(target.lstat(), "st_file_attributes", 0) & 0x400:
        raise ValueError("Target must not be a link or junction")
    root = target.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Inspection target must be a local directory")
    result = Inventory(root)
    total = 0
    pending = [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    result.entries += 1
                    if result.entries > max_entries:
                        result.gaps.append("Entry limit exceeded")
                        return result
                    path = Path(entry.path)
                    name = path.relative_to(root).as_posix()
                    # DirEntry's Windows cached stat omits link count/inode on some versions.
                    info = path.lstat()
                    if entry.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                        result.gaps.append(f"Link/reparse point skipped: {name}")
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if entry.name in EXCLUDED:
                            result.excluded.append(name)
                        elif depth >= 32:
                            result.gaps.append(f"Depth limit: {name}")
                        else:
                            pending.append((path, depth + 1))
                        continue
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        result.gaps.append(f"Special/hardlinked file skipped: {name}")
                        continue
                    if info.st_size > max_file or total + info.st_size > max_total:
                        result.gaps.append(f"Size limit: {name}")
                        continue
                    # O_NONBLOCK avoids FIFO races; O_NOFOLLOW blocks final-link races on POSIX.
                    fd = os.open(
                        path,
                        os.O_RDONLY
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_NONBLOCK", 0)
                        | getattr(os, "O_BINARY", 0),
                    )
                    with os.fdopen(fd, "rb") as stream:
                        actual = os.fstat(stream.fileno())
                        if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                            result.gaps.append(f"File changed: {name}")
                            continue
                        if (info.st_ino, info.st_dev) != (actual.st_ino, actual.st_dev):
                            result.gaps.append(f"File changed: {name}")
                            continue
                        data = stream.read(max_file + 1)
                    if len(data) > max_file or total + len(data) > max_total:
                        result.gaps.append(f"Size limit: {name}")
                        continue
                    result.files[name] = data
                    total += len(data)
        except OSError as exc:
            result.gaps.append(f"Unreadable directory/file: {type(exc).__name__}")
    return result


def snapshot(result: Inventory, destination: Path) -> None:
    for name, data in result.files.items():
        # Scanner-controlled configuration is never copied to the analysis snapshot.
        if Path(name).name in CONFIG or Path(name).name.startswith(".trivyignore"):
            continue
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
