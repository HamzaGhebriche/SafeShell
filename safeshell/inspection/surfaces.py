"""Conservative execution surfaces and literal invocation edges, not full program analysis."""

import configparser
import json
import posixpath
import re
import tomllib
from pathlib import PurePosixPath

from .inventory import Inventory
from .literals import invocations, member_line, without_comments
from .models import Finding, Graph

PATTERNS = {
    "external_download": r"\b(curl|wget|Invoke-WebRequest|DownloadString|DownloadFile)\b|https?://",
    "sensitive_access": r"\.ssh\b|\.aws\b|\.config\b|credentials|shell_history|\.bash_history|PSReadLine",
    "persistence": r"\b(crontab|schtasks|New-Service)\b|Startup[/\\]|\.bashrc|\.profile|PowerShell[/\\].*profile",
    "destructive": r"\brm\s+-[rf]+\b|Remove-Item.*-Recurse|\b(mkfs|diskpart|netsh|useradd)\b",
    "obfuscation": r"-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|base64.*(?:bash|sh|exec)|[A-Za-z0-9+/]{300,}={0,2}",
}
SCRIPT = {".sh", ".bash", ".ps1", ".bat", ".cmd", ".js", ".mjs", ".cjs", ".py"}
AUTOMATIC = {"preinstall", "install", "postinstall", "prepare"}


def analyze(inv: Inventory) -> tuple[list[Finding], Graph, list[str]]:
    graph = Graph()
    findings: list[Finding] = []
    gaps: list[str] = []
    file_nodes: dict[str, str] = {}
    texts: dict[str, str] = {}
    automatic: list[str] = []
    commands: list[tuple[str, str, str]] = []
    npm_scripts: dict[tuple[str, str], str] = {}
    ambiguous_cwd: set[str] = set()

    def add(category, title, file, line, evidence, node, confidence="MEDIUM"):
        if len(findings) >= 4000:
            if "Native finding limit exceeded" not in gaps:
                gaps.append("Native finding limit exceeded")
            return
        finding = Finding(
            f"SS-NATIVE-{len(findings) + 1:04}",
            "SafeShell",
            category,
            "HIGH" if category != "execution" else "MEDIUM",
            confidence,
            title,
            file=file,
            line=line,
            evidence=evidence,
            metadata={"node": node},
        )
        findings.append(finding)

    def command(file, label, body, auto=False, line=None):
        if len(commands) >= 1000:
            if "Execution command limit exceeded" not in gaps:
                gaps.append("Execution command limit exceeded")
            return
        if len(body) > 16384:
            gaps.append(f"Command truncated: {file}")
            body = body[:16384]
        trigger = graph.node("trigger", label, file, line, auto)
        node = graph.node("command", body, file, line)
        graph.edge(trigger, node, "triggers")
        graph.edge(file_nodes[file], node, "invokes")
        commands.append((node, file, body))
        if auto:
            automatic.append(trigger)
        add("execution", label, file, line, body, node, "HIGH")
        return node

    for name, data in inv.files.items():
        if len(texts) >= 2000:
            gaps.append("Native text-file limit exceeded")
            break
        path = PurePosixPath(name)
        recognized = (
            path.suffix.lower() in SCRIPT
            or path.name
            in {
                "package.json",
                "pyproject.toml",
                "setup.cfg",
                "Dockerfile",
                "Makefile",
                "makefile",
                "Justfile",
                "justfile",
                "Taskfile.yml",
            }
            or name.startswith((".github/workflows/", ".vscode/", ".claude/", ".cursor/"))
            or name == ".mcp.json"
        )
        try:
            encoding = (
                "utf-16"
                if path.suffix.lower() == ".ps1" and data.startswith((b"\xff\xfe", b"\xfe\xff"))
                else "utf-8-sig"
            )
            text = data.decode(encoding)
        except UnicodeDecodeError:
            if recognized:
                gaps.append(f"Unsupported execution-file encoding: {name}")
            continue
        if "\0" in text:
            if recognized:
                gaps.append(f"Binary/NUL content in execution file: {name}")
            continue
        if len(text) > 131072:
            gaps.append(f"Native text analysis truncated: {name}")
            text = text[:131072]
        if len(text.splitlines()) > 2000:
            gaps.append(f"Native line analysis truncated: {name}")
            text = "\n".join(text.splitlines()[:2000])
        texts[name] = text
        file_nodes[name] = graph.node("file", name, name)

    for name, text in texts.items():
        path = PurePosixPath(name)
        base = path.name
        try:
            if base == "package.json":
                manifest = json.loads(text)
                for key, value in manifest.get("scripts", {}).items():
                    if isinstance(value, str):
                        node = command(
                            name,
                            f"npm {key}",
                            value,
                            key in AUTOMATIC,
                            member_line(text, key, value),
                        )
                        if node:
                            npm_scripts[(name, key)] = node
            elif base == "pyproject.toml":
                manifest_data = tomllib.loads(text)
                build = manifest_data.get("build-system", {})
                if build:
                    command(
                        name,
                        "Python build backend (code not resolved)",
                        str(build.get("build-backend", "unspecified")),
                        True,
                    )
                    gaps.append(f"Dynamic Python build backend not resolved: {name}")
                for key, value in manifest_data.get("project", {}).get("scripts", {}).items():
                    command(name, f"Python entry point {key}", str(value))
            elif base == "setup.cfg":
                cfg = configparser.ConfigParser(interpolation=None)
                cfg.read_string(text)
                if cfg.has_section("options.entry_points"):
                    for key, value in cfg.items("options.entry_points"):
                        command(name, f"Python entry point {key}", value)
            elif base == "setup.py":
                command(name, "Python packaging executes setup.py", f'python "{name}"', True, 1)
            elif base == "Dockerfile" or base.startswith("Dockerfile."):
                for number, line in enumerate(text.splitlines(), 1):
                    if re.match(r"\s*(RUN|CMD|ENTRYPOINT)\b", line, re.I):
                        command(name, "Container build/runtime", line, True, number)
            elif base in {"Makefile", "makefile", "Justfile", "justfile", "Taskfile.yml"}:
                for number, line in enumerate(text.splitlines(), 1):
                    if line.startswith("\t") or re.match(r"\s+-\s+", line):
                        command(name, "Build task (manual)", line.strip(), line=number)
            elif name.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
                # Do not interpret YAML tags, aliases or expressions. Literal line evidence only.
                gaps.append(f"Workflow literal extraction only: {name}")
                for number, line in enumerate(text.splitlines(), 1):
                    if re.search(r"\b(run|uses|permissions):", line):
                        command(name, "GitHub workflow (conditional)", line.strip(), line=number)
                        if "write-all" in line or (
                            "uses:" in line and not re.search(r"@[a-f0-9]{40}\b", line)
                        ):
                            add(
                                "repository_posture",
                                "Workflow permissions or unpinned action",
                                name,
                                number,
                                line,
                                file_nodes[name],
                                "CONTEXTUAL",
                            )
            elif name == ".vscode/tasks.json":
                for task in json.loads(text).get("tasks", []):
                    if isinstance(task.get("command"), str):
                        auto = task.get("runOptions", {}).get("runOn") == "folderOpen"
                        command(
                            name,
                            "VS Code task",
                            task["command"],
                            auto,
                            member_line(text, "command", task["command"]),
                        )
                        if task.get("options", {}).get("cwd"):
                            ambiguous_cwd.add(name)
                            gaps.append(f"VS Code task cwd not resolved: {name}")
            elif name in {
                ".claude/settings.json",
                ".claude/settings.local.json",
                ".cursor/mcp.json",
                ".vscode/mcp.json",
                ".mcp.json",
            }:
                data = json.loads(text)

                def walk(value):
                    if isinstance(value, dict):
                        if isinstance(value.get("command"), str):
                            command(
                                name,
                                "Agent hook/server (conditional)",
                                value["command"],
                                line=member_line(text, "command", value["command"]),
                            )
                        for child in value.values():
                            walk(child)
                    elif isinstance(value, list):
                        for child in value:
                            walk(child)

                walk(data)
            elif base in {"AGENTS.md", "CLAUDE.md"}:
                add(
                    "other",
                    "Agent instructions present; semantics not evaluated",
                    name,
                    None,
                    "Configuration identified",
                    file_nodes[name],
                    "CONTEXTUAL",
                )
        except (ValueError, TypeError, AttributeError, RecursionError, configparser.Error) as exc:
            gaps.append(f"Malformed/unsupported manifest {name}: {type(exc).__name__}")

    # Analyze parsed command values separately, so a manual sibling cannot lend its
    # evidence to an automatic hook on the same manifest line.
    behaviors = list(commands)
    for name, text in texts.items():
        if PurePosixPath(name).suffix.lower() not in SCRIPT:
            continue
        commands.append((file_nodes[name], name, text))
        behaviors.append((file_nodes[name], name, text))
    for parent, name, body in behaviors:
        source = parent == file_nodes[name]
        suffix = PurePosixPath(name).suffix.lower() if source else ".sh"
        cleaned = without_comments(body, suffix)
        parent_line = next(n["line"] for n in graph.nodes if n["id"] == parent)
        for offset, (original, line) in enumerate(zip(body.splitlines(), cleaned.splitlines())):
            number = offset + 1 if source else parent_line
            for category, pattern in PATTERNS.items():
                if re.search(pattern, line, re.I):
                    action = graph.node(
                        category, category.replace("_", " "), name, number, context=parent
                    )
                    relation = {
                        "external_download": "downloads",
                        "destructive": "writes",
                        "persistence": "writes",
                        "obfuscation": "launches",
                    }.get(category, "reads")
                    graph.edge(parent, action, relation)
                    add(
                        category,
                        category.replace("_", " ").capitalize(),
                        name,
                        number,
                        original[:2000] if source else body[:2000],
                        action,
                    )

    # Only literal process-launch contexts produce invocation edges; no basename
    # guessing, comment/data references, variable expansion or implicit script cwd.
    for node, name, body in commands:
        source = node == file_nodes[name]
        if name in ambiguous_cwd:
            gaps.append(f"Process working directory not resolved: {name}")
            continue
        try:
            references, unresolved = invocations(body, PurePosixPath(name).suffix, source)
        except (ValueError, TypeError, RecursionError):
            references, unresolved = [], True
        if unresolved:
            gaps.append(f"Dynamic/unsupported process invocation in {name}")
        for index, (kind, raw) in enumerate(references):
            if index >= 100:
                gaps.append(f"Literal reference limit exceeded: {name}")
                break
            if kind == "npm":
                selected_node = npm_scripts.get((name, raw))
                if selected_node:
                    graph.edge(node, selected_node, "invokes")
                else:
                    gaps.append(f"Unresolved npm script in {name}: {raw}")
                continue
            candidates = [posixpath.normpath(raw)]
            if PurePosixPath(name).name == "package.json":
                candidates = [posixpath.normpath(str(PurePosixPath(name).parent / raw))]
            selected = next((x for x in candidates if x in file_nodes), None)
            if selected:
                graph.edge(node, file_nodes[selected], "invokes")
                if (
                    PurePosixPath(name).name == "package.json"
                    and str(PurePosixPath(name).parent) != "."
                ):
                    ambiguous_cwd.add(selected)
            else:
                gaps.append(f"Unresolved literal script reference in {name}: {raw}")
    reached = set().union(*(graph.reachable(n) for n in automatic)) if automatic else set()
    for finding in findings:
        finding.execution_relevant = finding.metadata["node"] in reached
        finding.metadata["reachability"] = (
            "potential automatic" if finding.execution_relevant else "unproven/manual"
        )
    return findings, graph, list(dict.fromkeys(gaps))
