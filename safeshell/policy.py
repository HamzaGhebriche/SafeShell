"""Strict policies can only narrow the built-in trust baseline."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
import os
import stat
import tomllib


@dataclass
class Policy:
    version: int = 1
    preset: str = "offline"
    workspace: str = "."
    network: str = "off"
    environment: list[str] = field(default_factory=list)
    confirmation: str = "risk"
    audit: str = "metadata"
    hard_denied: list[str] = field(
        default_factory=lambda: ["privilege", "credentials", "containers"]
    )


PRESETS = {"offline": "risk", "development": "risk", "strict": "always"}
BASE_DENIALS = {"privilege", "credentials", "containers"}
ENV_ALLOWLIST = {"LANG", "LC_ALL", "TZ"}


def load(workspace: Path, explicit: Path | None = None, reviewed: bool = False) -> Policy:
    path = explicit if explicit is not None else workspace / ".safeshell.toml"
    if path.is_symlink():
        raise ValueError("Policy cannot be a symlink")
    if not path.exists():
        if explicit:
            raise ValueError("Explicit policy does not exist")
        return Policy()
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > 65536:
        raise ValueError("Policy must be a regular, non-symlink file below 64 KiB")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(data) - set(asdict(Policy())):
        raise ValueError("Unknown policy keys")
    preset = data.get("preset", "offline")
    if not isinstance(preset, str) or preset not in PRESETS:
        raise ValueError("Unknown preset")
    data.setdefault("confirmation", PRESETS[preset])
    policy = Policy(**data)
    if type(policy.version) is not int or policy.version != 1:
        raise ValueError("Only policy version 1 is supported")
    if policy.network != "off":
        raise ValueError("Only network = 'off' is enforced")
    if not isinstance(policy.workspace, str) or policy.workspace != ".":
        raise ValueError("Only workspace = '.' is supported; select the root with --workspace")
    if not isinstance(policy.environment, list) or any(
        type(x) is not str or x not in ENV_ALLOWLIST for x in policy.environment
    ):
        raise ValueError("Environment permissions are restricted to LANG, LC_ALL, TZ")
    if policy.confirmation not in ("risk", "always"):
        raise ValueError("Confirmation cannot weaken the built-in risk requirement")
    if policy.preset == "strict" and policy.confirmation != "always":
        raise ValueError("Strict preset requires confirmation = 'always'")
    if policy.audit not in ("metadata", "redacted"):
        raise ValueError("Audit must be metadata or redacted")
    if (policy.environment or policy.audit == "redacted") and not reviewed:
        raise ValueError(
            "Policy expands inherited environment or stored command metadata; review the file and pass --review-policy"
        )
    if not isinstance(policy.hard_denied, list) or any(
        type(x) is not str for x in policy.hard_denied
    ):
        raise ValueError("hard_denied must be a list of capability names")
    if not BASE_DENIALS <= set(policy.hard_denied) or set(policy.hard_denied) - (
        BASE_DENIALS | {"network"}
    ):
        raise ValueError(
            "Hard denials must include privilege, credentials, containers; unsupported capability"
        )
    return policy


def evaluate(report: dict, policy: Policy) -> dict:
    denials = sorted(set(report["requested_capabilities"]) & set(policy.hard_denied))
    if not report["syntax_supported"]:
        denials.append("unsupported-shell-syntax")
    return {
        "permitted": not denials,
        "denials": denials,
        "confirmation_required": policy.confirmation == "always" or report["risk"] != "low",
    }


def environment(policy: Policy) -> dict[str, str]:
    result = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/sandbox",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for name in policy.environment:
        value = os.environ.get(name)
        if value and len(value) < 256 and all(c.isprintable() for c in value):
            result[name] = value
    return result


def template(preset: str) -> str:
    return (
        f'version = 1\npreset = "{preset}"\nworkspace = "."\nnetwork = "off"\n'
        f'environment = []\nconfirmation = "{PRESETS[preset]}"\naudit = "metadata"\n'
        'hard_denied = ["privilege", "credentials", "containers"]\n'
    )
