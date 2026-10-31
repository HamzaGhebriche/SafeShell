"""A deliberately limited shell grammar; never evaluates shell input."""

from dataclasses import asdict, dataclass


@dataclass
class Finding:
    id: str
    severity: str
    explanation: str
    remediation: str
    evidence: str
    token_index: int | None = None


@dataclass
class Command:
    argv: list[str]
    redirects: list[tuple[str, str]]


class Unsupported(ValueError):
    pass


def lex(source: str) -> tuple[list[str], set[int]]:
    """Tokenize POSIX quotes/escapes while retaining operator provenance."""
    tokens, operators = [], set()
    word, active, quote, i = "", False, None, 0

    def flush():
        nonlocal word, active
        if active:
            tokens.append(word)
            word, active = "", False

    while i < len(source):
        char = source[i]
        if char == "\\" and quote != "'":
            i += 1
            if i >= len(source):
                raise Unsupported("Trailing escape")
            following = source[i]
            if quote == '"' and following not in ("$", "`", '"', "\\"):
                word += "\\"
            word += following
            active = True
        elif quote:
            if char == quote:
                quote = None
            else:
                word += char
        elif char in ("'", '"'):
            quote, active = char, True
        elif char.isspace():
            flush()
        elif char == "#" and not active:
            break
        elif char in "|&;<>":
            if char in "<>" and active and word.isdigit():
                raise Unsupported("File descriptor redirection")
            flush()
            operator = char
            while i + 1 < len(source) and source[i + 1] in "|&;<>":
                i += 1
                operator += source[i]
            operators.add(len(tokens))
            tokens.append(operator)
        else:
            word += char
            active = True
        i += 1
    if quote:
        raise Unsupported("Unclosed quote")
    flush()
    return tokens, operators


def parse_shell(source: str) -> tuple[list[Command], list[str]]:
    """Recursive descent over list -> pipeline -> command with a quote-aware lexer.

    Only simple commands, pipelines, &&/||/; and file redirects are supported.
    Expansions/compound constructs are explicitly rejected rather than guessed.
    """
    if any(x in source for x in ("$", "`", "\n", "\r", "(", ")", "{", "}", "<<")):
        raise Unsupported("Expansion, substitution, multiline or compound shell syntax")
    tokens, punctuation = lex(source)
    commands: list[Command] = []
    operators: list[str] = []
    i = 0

    def command():
        nonlocal i
        words, redirects = [], []
        while i < len(tokens) and not (i in punctuation and tokens[i] in ("|", "&&", "||", ";")):
            token = tokens[i]
            if i in punctuation and token in (">", ">>", "<"):
                i += 1
                if i == len(tokens) or i in punctuation:
                    raise Unsupported("Missing redirect target")
                redirects.append((token, tokens[i]))
            elif i in punctuation:
                raise Unsupported("Background jobs or descriptor redirection")
            else:
                words.append(token)
            i += 1
        if not words:
            raise Unsupported("Expected a simple command")
        if words[0] in ("if", "for", "while", "case", "function", "until", "!", "then"):
            raise Unsupported("Compound commands are outside the supported grammar")
        if "=" in words[0]:
            raise Unsupported("Shell assignment syntax")
        commands.append(Command(words, redirects))

    def pipeline():
        nonlocal i
        command()
        while i < len(tokens) and i in punctuation and tokens[i] == "|":
            operators.append(tokens[i])
            i += 1
            command()

    if not tokens:
        raise Unsupported("Empty command")
    pipeline()
    while i < len(tokens):
        op = tokens[i]
        if op not in ("&&", "||", ";"):
            raise Unsupported("Unsupported operator")
        operators.append(op)
        i += 1
        if i == len(tokens) and op == ";":
            break
        pipeline()
    return commands, operators


def inspect(argv: list[str], shell: bool = False) -> dict:
    findings: list[Finding] = []
    unknowns = [
        "Static inspection cannot prove behavior; executable code and workspace files may change."
    ]
    supported = True
    commands = [Command(argv, [])]
    operators: list[str] = []
    if shell:
        try:
            commands, operators = parse_shell(argv[0])
        except ValueError as exc:
            supported = False
            commands = [Command([], [])]
            unknowns.append(str(exc))

    def add(rule, severity, message, remedy, evidence, index=None):
        findings.append(Finding(rule, severity, message, remedy, evidence, index))

    capabilities = set()
    for command in commands:
        words = command.argv
        if not words:
            continue
        name = words[0].replace("\\", "/").split("/")[-1]
        joined = " ".join(words)
        if name in ("env", "printenv", "set"):
            add(
                "SS011",
                "medium",
                "Environment access requested.",
                "Pass only necessary variables explicitly.",
                name,
            )
        if name in ("cp", "mv", "install", "tee", "touch", "mkdir", "chmod", "chown", "ln"):
            capabilities.add("filesystem-write")
            if any(w.startswith(("/etc/", "/usr/", "/sys/", "/boot/")) for w in words[1:]):
                add(
                    "SS005",
                    "high",
                    "Filesystem operation references a system directory.",
                    "Write inside the workspace.",
                    "system path",
                )
            if any(
                any(x in w for x in (".bashrc", ".profile", ".zshrc", "autostart"))
                for w in words[1:]
            ):
                add(
                    "SS009",
                    "high",
                    "Filesystem operation references a startup file.",
                    "Avoid persistent startup changes.",
                    "startup path",
                )
        for index, word in enumerate(words):
            if any(
                x in word.lower()
                for x in (
                    ".ssh",
                    ".aws",
                    ".kube",
                    ".docker",
                    ".git-credentials",
                    "credentials",
                    "id_rsa",
                )
            ):
                add(
                    "SS004",
                    "high",
                    "Credential-related path referenced.",
                    "Remove credential access.",
                    "credential path",
                    index,
                )
                capabilities.add("credentials")
            if any(x in word for x in ("$", "`", "*", "?", "~")):
                unknowns.append("Dynamic paths or environment expansion cannot be resolved.")
        if name in ("curl", "wget"):
            capabilities.add("network")
            add(
                "SS001",
                "medium",
                "Remote content requested.",
                "Fetch and verify content separately.",
                name,
            )
        if name in ("sudo", "su", "doas", "pkexec"):
            capabilities.add("privilege")
            add(
                "SS002",
                "high",
                "Administrator elevation requested.",
                "Use an unprivileged workflow.",
                name,
            )
        if name in ("rm", "rmdir", "dd", "mkfs", "shred", "truncate"):
            add(
                "SS003",
                "high",
                "Destructive filesystem operation.",
                "Use a disposable workspace or backup.",
                name,
            )
        if name in (
            "npm",
            "pnpm",
            "yarn",
            "pip",
            "pip3",
            "cargo",
            "make",
            "pytest",
            "python",
            "python3",
            "node",
        ):
            add(
                "SS006",
                "medium",
                "Builds, packages and tests can execute arbitrary code, including hooks.",
                "Review code and dependency hooks.",
                name,
            )
        if name in ("docker", "podman"):
            capabilities.add("containers")
            add(
                "SS007",
                "high",
                "Container invocation may request host mounts or privileges.",
                "Do not expose host container services.",
                name,
            )
        if "docker.sock" in joined or "--privileged" in words:
            capabilities.add("privilege")
        if name in (
            "bash",
            "sh",
            "zsh",
            "eval",
            "exec",
            "source",
            ".",
            "env",
            "python",
            "python3",
            "node",
            "perl",
            "ruby",
            "base64",
            "openssl",
            "powershell",
            "pwsh",
            "cmd",
        ):
            add(
                "SS008",
                "medium",
                "Nested interpreter or encoding can hide executable behavior.",
                "Inspect the referenced source separately.",
                name,
            )
            unknowns.append("Nested interpreter contents are not recursively analyzed.")
        for op, target in command.redirects:
            capabilities.add("filesystem-read" if op == "<" else "filesystem-write")
            if op != "<" and target.startswith(("/etc/", "/usr/", "/sys/", "/boot/")):
                add(
                    "SS005",
                    "high",
                    "System-directory write requested.",
                    "Write inside the workspace.",
                    "system path",
                )
            if any(x in target for x in (".bashrc", ".profile", ".zshrc", "autostart")):
                add(
                    "SS009",
                    "high",
                    "Startup file modification requested.",
                    "Avoid persistent startup changes.",
                    "startup path",
                )
        unknowns.append(
            "Aliases, executable identity, functions and runtime inputs are not resolved."
        )
    if (
        operators
        and any(c.argv and c.argv[0] in ("curl", "wget") for c in commands)
        and any(c.argv and c.argv[0] in ("bash", "sh") for c in commands)
    ):
        add(
            "SS010",
            "high",
            "Remote download and shell execution occur in one command list.",
            "Download, verify and inspect before execution.",
            "download | shell",
        )
    if shell and any(x in argv[0] for x in ("$", "`")):
        add(
            "SS011",
            "medium",
            "Environment access or command substitution detected.",
            "Use explicit arguments and paths.",
            "dynamic shell expression",
        )
    severity = (
        "high"
        if any(f.severity == "high" for f in findings)
        else "medium"
        if findings or not supported
        else "low"
    )
    return {
        "schema_version": 1,
        "mode": "shell" if shell else "argv",
        "risk": severity,
        "findings": [asdict(f) for f in findings],
        "requested_capabilities": sorted(capabilities),
        "predicted_behavior": ["Pipeline/chaining" if operators else "Program invocation"],
        "unknowns": sorted(set(unknowns)),
        "syntax_supported": supported,
    }
