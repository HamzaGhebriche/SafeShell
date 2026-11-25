"""Literal process launches only: filenames in comments/data are not invocation edges."""

import ast
import io
import json
import re
import shlex
import tokenize
from pathlib import PurePosixPath

SCRIPT = {".sh", ".bash", ".ps1", ".bat", ".cmd", ".js", ".mjs", ".cjs", ".py"}
INTERPRETERS = {
    "node",
    "python",
    "python3",
    "python3.11",
    "python3.12",
    "py",
    "sh",
    "bash",
    "powershell",
    "pwsh",
    "cmd",
}


def without_comments(text: str, suffix: str) -> str:
    if suffix == ".py":
        lines = text.splitlines(keepends=True)
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type == tokenize.COMMENT:
                    line = lines[token.start[0] - 1]
                    lines[token.start[0] - 1] = (
                        line[: token.start[1]] + " " * len(token.string) + line[token.end[1] :]
                    )
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass
        return "".join(lines)
    # Preserve strings and line positions. Never interpret escapes or evaluate expressions.
    pattern = r""""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' """.rstrip()
    comments = r"|/\*[\s\S]*?\*/|//[^\n]*" if suffix in {".js", ".mjs", ".cjs"} else r"|\#[^\n]*"
    return re.sub(
        pattern + comments,
        lambda m: (
            m.group()
            if m.group().startswith(('"', "'"))
            else "".join("\n" if c == "\n" else " " for c in m.group())
        ),
        text,
    )


def member_line(text: str, key: str, value: str) -> int | None:
    """Return a JSON member line only if its decoded key/value occurrence is unambiguous."""
    decoder = json.JSONDecoder()
    locations = []
    for match in re.finditer(r'"(?:\\.|[^"\\])*"\s*:\s*', text):
        try:
            candidate, _ = decoder.raw_decode(text, match.start())
            actual, _ = decoder.raw_decode(text, match.end())
            if candidate == key and actual == value:
                locations.append(text.count("\n", 0, match.start()) + 1)
        except ValueError:
            continue
    return locations[0] if len(locations) == 1 else None


def shell_words(text: str) -> list[list[str]]:
    groups = []
    for line in text.splitlines():
        lexer = shlex.shlex(line, posix=False, punctuation_chars=";&|")
        lexer.whitespace_split, lexer.commenters = True, ""
        current: list[str] = []
        for word in lexer:
            if word and all(c in ";&|" for c in word):
                if current:
                    groups.append(current)
                    current = []
            else:
                current.append(word.strip("\"'"))
        if current:
            groups.append(current)
    return groups


def invocations(text: str, suffix: str, source: bool) -> tuple[list[tuple[str, str]], bool]:
    suffix = suffix.lower()
    commands: list[list[str]] = []
    unresolved = False
    text = without_comments(text, suffix)
    if source and suffix == ".py":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return [], True
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute) or not isinstance(
                node.func.value, ast.Name
            ):
                continue
            name = node.func.value.id + "." + node.func.attr
            if name not in {
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "os.system",
            }:
                continue
            argument = (
                # A custom working directory or dynamic keyword mapping invalidates
                # the root-relative assumption; retain an explicit coverage gap.
                node.args[0]
                if node.args
                else next((k.value for k in node.keywords if k.arg == "args"), None)
            )
            if any(keyword.arg in {"cwd", None} for keyword in node.keywords):
                unresolved = True
                continue
            try:
                value = ast.literal_eval(argument) if argument is not None else None
            except (ValueError, TypeError, RecursionError):
                value = None
            if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
                commands.append(list(value))
            elif isinstance(value, str):
                commands.extend(shell_words(value))
            else:
                unresolved = True
    elif source and suffix in {".js", ".mjs", ".cjs"}:
        launches = re.compile(
            r"\b(?:spawn|spawnSync|execFile|execFileSync|exec|execSync)\s*\(\s*(['\"])(.*?)\1(?:\s*,\s*\[([^\]]*)\])?",
            re.S,
        )
        for match in launches.finditer(text):
            if re.match(r"\s*,\s*\{[^}]*\bcwd\s*:", text[match.end() : match.end() + 300]):
                unresolved = True
                continue
            if match[3] is None:
                commands.extend(shell_words(match[2]))
            else:
                arguments = re.findall(r"(['\"])(.*?)\1", match[3])
                remainder = re.sub(r"(['\"])(.*?)\1", "", match[3]).replace(",", "").strip()
                if remainder:
                    unresolved = True
                else:
                    commands.append([match[2], *(value for _, value in arguments)])
        if re.search(
            r"\b(?:spawn|spawnSync|execFile|execFileSync|exec|execSync)\s*\(\s*[^'\"\s]", text
        ):
            unresolved = True
    else:
        try:
            commands = shell_words(text)
        except ValueError:
            return [], True
    result = []
    for words in commands:
        if not words:
            continue
        executable = PurePosixPath(words[0].replace("\\", "/")).name.lower().removesuffix(".exe")
        if executable in {"cd", "pushd", "popd", "set-location"}:
            unresolved = True
            break
        if executable == "npm" and len(words) >= 3 and words[1] in {"run", "run-script"}:
            result.append(("npm", words[2]))
        elif executable in INTERPRETERS:
            if any(
                word in {"-c", "-e", "--eval", "-Command", "-EncodedCommand", "-m"}
                for word in words[1:]
            ):
                unresolved = True
                continue
            script = next(
                (word for word in words[1:] if PurePosixPath(word).suffix.lower() in SCRIPT), None
            )
            if script:
                result.append(("file", script.replace("\\", "/")))
        elif PurePosixPath(words[0]).suffix.lower() in SCRIPT:
            result.append(("file", words[0].replace("\\", "/")))
    return result, unresolved
