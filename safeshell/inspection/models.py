"""Versioned evidence models independent of CLI and external scanners."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    finding_id: str
    source: str
    category: str
    severity: str
    confidence: str
    title: str
    description: str = ""
    file: str | None = None
    line: int | None = None
    evidence: Any = None
    identifiers: list[str] = field(default_factory=list)
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    execution_relevant: bool = False
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        for name in (
            "finding_id",
            "source",
            "category",
            "severity",
            "confidence",
            "title",
            "description",
        ):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"Invalid finding field: {name}")
        for name in ("file", "package", "installed_version", "fixed_version"):
            if getattr(self, name) is not None and not isinstance(getattr(self, name), str):
                raise TypeError(f"Invalid finding field: {name}")
        if self.line is not None and (type(self.line) is not int or self.line < 1):
            raise ValueError("Invalid finding line")
        if not isinstance(self.identifiers, list) or any(
            not isinstance(x, str) for x in self.identifiers
        ):
            raise TypeError("Invalid finding identifiers")
        if not isinstance(self.metadata, dict) or type(self.execution_relevant) is not bool:
            raise TypeError("Invalid finding metadata/reachability")


@dataclass
class EngineResult:
    source: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""
    version: str | None = None
    exit_code: int | None = None


@dataclass
class Graph:
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)

    def __post_init__(self):
        self._node_index = {
            (
                n["kind"],
                n["label"],
                n["file"],
                n.get("line"),
                n.get("automatic", False),
                n.get("context"),
            ): n["id"]
            for n in self.nodes
        }
        self._edge_index = {(e["source"], e["target"], e["relation"]) for e in self.edges}

    def node(
        self,
        kind: str,
        label: str,
        file: str | None = None,
        line: int | None = None,
        automatic: bool = False,
        context: str | None = None,
    ) -> str:
        key = (kind, label, file, line, automatic, context)
        if key in self._node_index:
            return self._node_index[key]
        identifier = f"n{len(self.nodes)}"
        self.nodes.append(
            {
                "id": identifier,
                "kind": kind,
                "label": label,
                "file": file,
                "line": line,
                "automatic": automatic,
                "context": context,
            }
        )
        self._node_index[key] = identifier
        return identifier

    def edge(self, source: str, target: str, relation: str) -> None:
        edge = {"source": source, "target": target, "relation": relation}
        key = (source, target, relation)
        if key not in self._edge_index:
            self.edges.append(edge)
            self._edge_index.add(key)

    def reachable(self, start: str) -> set[str]:
        seen, pending = set(), [start]
        adjacency: dict[str, list[str]] = {}
        for edge in self.edges:
            adjacency.setdefault(edge["source"], []).append(edge["target"])
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            pending.extend(adjacency.get(current, []))
        return seen
