"""Small Debian/Ubuntu runtime inventory; no executable is run to discover dependencies.

Only fixed system programs, packaged Python stdlib code, and transitive ELF dependencies
are exposed. This is mount selection, not an ELF loader or a new sandbox backend.
"""

import hashlib
import json
import os
import re
import stat
import struct
from functools import lru_cache
from pathlib import Path

PROGRAMS = (
    "bash",
    "sh",
    "dash",
    "true",
    "false",
    "printf",
    "cat",
    "echo",
    "env",
    "id",
    "sleep",
    "sort",
    "ls",
    "head",
    "tail",
    "wc",
    "mkdir",
    "rm",
    "touch",
    "cp",
    "mv",
    "python3",
)


def elf_dependencies(data: bytes) -> tuple[list[str], str | None]:
    """Read little-endian ELF64 PT_DYNAMIC/LOAD/INTERP, with bounds checks."""
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Runtime requires little-endian ELF64 files")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[2] not in (62, 183):
        raise ValueError("Runtime ELF architecture unsupported")
    offset, size, count = header[5], header[9], header[10]
    if size != 56 or count > 256 or offset + size * count > len(data):
        raise ValueError("Invalid runtime ELF program headers")
    loads, dynamic, interpreter = [], None, None
    for index in range(count):
        kind, _, file_offset, address, _, file_size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + size * index
        )
        if file_offset + file_size > len(data):
            raise ValueError("Runtime ELF segment exceeds file")
        if kind == 1:
            loads.append((address, file_offset, file_size))
        elif kind == 2:
            dynamic = (file_offset, file_size)
        elif kind == 3:
            interpreter = data[file_offset : file_offset + file_size].rstrip(b"\0").decode("ascii")
            if not re.fullmatch(r"/(?:usr/)?lib[^ ]*/ld[^/]+", interpreter):
                raise ValueError("Unexpected runtime ELF interpreter")
    needed, strings = [], None
    if dynamic:
        start, length = dynamic
        if length % 16:
            raise ValueError("Invalid runtime dynamic segment")
        for position in range(start, start + length, 16):
            tag, value = struct.unpack_from("<qQ", data, position)
            if tag == 0:
                break
            if tag == 1:
                needed.append(value)
            elif tag == 5:
                strings = value
    if not needed:
        return [], interpreter
    for address, file_offset, file_size in loads:
        if strings is not None and address <= strings < address + file_size:
            table = file_offset + strings - address
            break
    else:
        raise ValueError("Runtime ELF string table absent")
    names = []
    for entry in needed:
        start = table + entry
        end = data.find(b"\0", start, min(start + 256, len(data)))
        if start >= len(data) or end < 0:
            raise ValueError("Invalid runtime dependency name")
        name = data[start:end].decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9_+.\-]+", name):
            raise ValueError("Runtime dependency must be a simple library name")
        names.append(name)
    return names, interpreter


def trusted_file(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not any(
        resolved.is_relative_to(Path(root)) for root in ("/usr/bin", "/usr/lib", "/lib", "/lib64")
    ):
        raise ValueError("Runtime file resolves outside approved system code directories")
    info = resolved.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or info.st_size > 128 * 1024 * 1024
    ):
        raise ValueError("Runtime files must be root-owned regular code, not group/world writable")
    for parent in resolved.parents:
        parent_info = parent.stat()
        if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
            raise ValueError(
                "Runtime parent directories must be root-owned and non-writable by other users"
            )
    return resolved


@lru_cache(maxsize=1)
def profile() -> tuple[tuple[str, str], ...]:
    machine = os.uname().machine
    triplet = {"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu"}.get(machine)
    if not triplet:
        raise RuntimeError("Alpha runtime supports Debian/Ubuntu ELF64 x86_64/aarch64 only")
    libraries = [
        Path(x) for x in (f"/lib/{triplet}", f"/usr/lib/{triplet}", "/lib64", "/lib", "/usr/lib")
    ]
    mounts, visited = {}, set()

    def add(path: Path, destination: Path | None = None):
        source = trusted_file(path)
        # /bin is a synthetic alias of /usr/bin, never a host directory bind.
        target = destination or path
        if str(target).startswith("/bin/"):
            target = Path("/usr/bin") / target.name
        mounts[str(target)] = str(source)
        mounts[str(source)] = str(source)
        if source in visited:
            return
        visited.add(source)
        data = source.read_bytes()
        if data.startswith(b"\x7fELF"):
            needed, interpreter = elf_dependencies(data)
            if interpreter:
                add(Path(interpreter))
            for name in needed:
                dependency = next(
                    (folder / name for folder in libraries if (folder / name).is_file()), None
                )
                if dependency is None:
                    raise RuntimeError(f"Required runtime library not found: {name}")
                add(dependency)

    for program in PROGRAMS:
        path = Path("/usr/bin") / program
        if not path.exists():
            raise RuntimeError(f"Required alpha runtime program is missing: {path}")
        add(path)
    python = Path("/usr/bin/python3").resolve()
    if not re.fullmatch(r"python3\.\d+", python.name):
        raise RuntimeError("Alpha runtime requires distro /usr/bin/python3")
    stdlib = Path("/usr/lib") / python.name
    manifests = [
        path
        for package in ("minimal", "stdlib")
        for path in Path("/var/lib/dpkg/info").glob(f"lib{python.name}-{package}*.list")
    ]
    if not manifests:
        raise RuntimeError("Debian/Ubuntu packaged Python stdlib manifests are required")
    code_count = 0
    for manifest in sorted(manifests):
        info = manifest.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Untrusted distro runtime manifest")
        for entry in manifest.read_text().splitlines():
            path = Path(entry)
            if path.name in ("sitecustomize.py", "usercustomize.py"):
                continue  # Never import host startup customizations from /etc.
            if path.is_relative_to(stdlib) and path.suffix in (".py", ".so") and path.is_file():
                add(path)
                code_count += 1
    if code_count < 100 or len(mounts) > 2000:
        raise RuntimeError("Unexpected packaged Python runtime inventory")
    # ctypes-based boundary checks and the system ABI use this explicit library.
    seccomp = next(
        (
            folder / "libseccomp.so.2"
            for folder in libraries
            if (folder / "libseccomp.so.2").is_file()
        ),
        None,
    )
    if seccomp is None:
        raise RuntimeError("libseccomp2 is required")
    add(seccomp)
    return tuple(sorted((source, target) for target, source in mounts.items()))


def manifest() -> dict:
    files = [{"source": source, "target": target} for source, target in profile()]
    encoded = json.dumps(files, sort_keys=True).encode()
    return {
        "profile": "debian-python-shell-v1",
        "programs": list(PROGRAMS),
        "files": files,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "excluded": ["/usr/local", "/usr/share", "/etc", "/var", "/opt", "/run", "host homes"],
    }
