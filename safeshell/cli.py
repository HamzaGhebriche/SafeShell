"""CLI presentation and orchestration."""

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import stat

from . import __version__, analysis, audit, backend, policy, runtime


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="safeshell", description="Run anything. Trust nothing.")
    result.add_argument("--version", action="version", version=__version__)
    subs = result.add_subparsers(dest="action", required=True)
    for action in ("explain", "run"):
        sub = subs.add_parser(action)
        sub.add_argument("--json", action="store_true")
        sub.add_argument("--no-color", action="store_true", help="Output is always color-free")
        sub.add_argument("--workspace", default=".")
        sub.add_argument("--policy", type=Path)
        sub.add_argument(
            "--review-policy",
            action="store_true",
            help="Acknowledge reviewed locale/audit expansion",
        )
        sub.add_argument("--shell", choices=["bash"])
        if action == "explain":
            sub.add_argument("--script", type=Path)
        else:
            sub.add_argument(
                "--yes", action="store_true", help="Approve permitted risk, never hard denials"
            )
            sub.add_argument("--timeout", type=int, default=300)
            sub.add_argument(
                "--max-output-bytes",
                type=int,
                default=1048576,
                help="Combined stdout/stderr limit (default 1 MiB; maximum 64 MiB)",
            )
        sub.add_argument("command", nargs=argparse.REMAINDER)
    sub = subs.add_parser("doctor")
    sub.add_argument("--json", action="store_true")
    sub = subs.add_parser("policy")
    sub.add_argument("operation", choices=["init", "validate"])
    sub.add_argument("--workspace", default=".")
    sub.add_argument("--preset", choices=list(policy.PRESETS), default="offline")
    sub.add_argument("--review-policy", action="store_true")
    sub.add_argument("--json", action="store_true")
    sub = subs.add_parser("history")
    sub.add_argument("operation", nargs="?", choices=["show", "delete"])
    sub.add_argument("id", nargs="?")
    sub.add_argument("--json", action="store_true")
    return result


def emit(value, machine: bool):
    if machine:
        print(json.dumps(value, ensure_ascii=True, sort_keys=True))
    else:
        print(audit.safe(str(value)))


def show_report(report: dict):
    print("SafeShell  /  command preview")
    print("  Risk       " + report["risk"].upper())
    if not report["findings"]:
        print(
            "  Findings   No known risk signals detected"
            if report["syntax_supported"]
            else "  Findings   Unsupported syntax; behavior is uncertain"
        )
    for finding in report["findings"]:
        print(f"  {finding['id']}  {audit.safe(finding['explanation'])}")
        print(f"           Remedy: {audit.safe(finding['remediation'])}")
    print("  Predicted  " + ", ".join(report["predicted_behavior"]))
    print(
        "  Requested  "
        + (", ".join(report["requested_capabilities"]) or "No capabilities identified")
    )
    print(
        "  Policy     "
        + (
            "PERMITTED"
            if report["decision"]["permitted"]
            else "DENIED: " + ", ".join(report["decision"]["denials"])
        )
    )
    print(
        "  Execution  "
        + ("Backend probe succeeded" if report["backend"]["available"] else "UNAVAILABLE")
    )
    print("             " + audit.safe(report["backend"]["reason"]))
    print("  Configured restrictions (effective only inside a successful sandbox):")
    for name, value in backend.RESTRICTIONS.items():
        print(f"    {name}: {value}")
    print(
        "  Residual   Workspace contents can be read, changed or deleted, including mounted secrets."
    )
    for item in report["unknowns"]:
        print("  Unknown    " + audit.safe(item))


def execute(args) -> int:
    machine = args.json
    if args.action == "doctor":
        capability = backend.discover()
        details = backend.describe(capability)
        if capability.available:
            details["runtime_manifest"] = runtime.manifest()
        emit(
            {"schema_version": 1, **details}
            if machine
            else f"SafeShell {__version__}\nBackend: {capability.backend}\nAvailable: {capability.available}\n{capability.reason}",
            machine,
        )
        return 0 if capability.available else 4
    if args.action == "history":
        if args.operation and not args.id:
            raise ValueError("Provide a session ID")
        if args.operation == "delete":
            audit.delete(args.id)
            emit({"schema_version": 1, "deleted": args.id}, machine)
        elif args.operation == "show":
            emit(audit.read(args.id), machine)
        else:
            records = audit.records()
            if machine:
                emit({"schema_version": 1, "sessions": records}, True)
            elif not records:
                print("No local sessions yet. Use safeshell run to record an execution decision.")
            else:
                for record in records:
                    emit(
                        f"{record.get('id')}  {record.get('status')}  exit={record.get('exit_code')}  {record.get('command')}",
                        False,
                    )
        return 0
    workspace = backend.workspace_path(args.workspace)
    if args.action == "policy":
        if args.operation == "init":
            with (workspace / ".safeshell.toml").open("x", encoding="utf-8") as stream:
                stream.write(policy.template(args.preset))
        loaded = policy.load(workspace, reviewed=args.review_policy)
        emit(
            {"schema_version": 1, "valid": True, "policy": asdict(loaded)}
            if machine
            else "Policy valid. Network off; trusted minimum restrictions preserved.",
            machine,
        )
        return 0
    argv = args.command
    if argv and argv[0] == "--":
        argv = argv[1:]
    shell = bool(args.shell)
    if getattr(args, "script", None):
        if argv or shell:
            raise ValueError("Use --script without a command or --shell")
        if not stat.S_ISREG(args.script.stat().st_mode) or args.script.stat().st_size > 1048576:
            raise ValueError("Script exceeds inspection limit of 1 MiB")
        argv = [args.script.read_text(encoding="utf-8")]
        shell = True
    if not argv or (shell and len(argv) != 1):
        raise ValueError(
            "Supply an argument vector after --, or exactly one string with --shell bash"
        )
    if sum(len(x) for x in argv) > 1048576 or any("\0" in x for x in argv):
        raise ValueError("Command contains NUL or exceeds 1 MiB")
    loaded = policy.load(workspace, args.policy, reviewed=args.review_policy)
    report = analysis.inspect(argv, shell)
    decision = policy.evaluate(report, loaded)
    capability = backend.describe(backend.discover())
    report.update(
        {
            "decision": decision,
            "backend": capability,
            "configured_policy": asdict(loaded),
            "execution_permitted": decision["permitted"] and capability["available"],
        }
    )
    if args.action == "explain":
        emit(report, True) if machine else show_report(report)
        return 0
    if args.timeout < 1 or args.timeout > 86400:
        raise ValueError("Timeout must be between 1 and 86400 seconds")
    if not 1 <= args.max_output_bytes <= 67108864:
        raise ValueError("Output limit must be between 1 and 67108864 bytes")
    record = audit.new_record(
        ["bash", "[script]"] if shell else argv, report, decision, capability, loaded.audit
    )
    record["limits"] = {
        "wall_seconds": args.timeout,
        "output_bytes": args.max_output_bytes,
        "cpu": None,
        "memory": None,
        "process_count": None,
        "disk": None,
    }
    audit.save(record)  # Audit failure prevents execution.
    status = 0
    if not decision["permitted"]:
        record["status"] = "denied"
        status = 3
    elif not capability["available"]:
        record["status"] = "backend-unavailable"
        status = 4
    elif decision["confirmation_required"] and not args.yes:
        if machine or not sys.stdin.isatty():
            record["status"] = "confirmation-required"
            status = 3
        else:
            show_report(report)
            if input("Type yes to allow this permitted risk: ") != "yes":
                record["status"] = "cancelled"
                status = 3
    if not status:
        record["status"] = "launching"
        audit.save(record)
        command = ["/bin/bash", "--noprofile", "--norc", "-c", argv[0]] if shell else argv

        def output(block):
            # Child output never enters stdout's JSON stream or persistent history.
            if not machine:
                sys.stderr.write(
                    "".join(
                        "\n" if c == "\n" else audit.safe(c)
                        for c in block.decode("utf-8", errors="replace")
                    )
                )
                sys.stderr.flush()

        try:
            status = backend.run(
                workspace, command, loaded, output, args.timeout, args.max_output_bytes
            )
            record["termination_reason"] = getattr(status, "termination_reason", "launcher-exit")
            record["status"] = {
                "output-limit": "output-limit",
                "timeout": "timed-out",
                "signal": "interrupted",
            }.get(record["termination_reason"], "finished")
        except (OSError, RuntimeError, ValueError) as exc:
            record["status"] = "launch-failed"
            record["error"] = audit.safe(str(exc))
            status = 4
    record["exit_code"] = status
    record["ended_at"] = datetime.now(timezone.utc).isoformat()
    audit.save(record)
    if machine:
        emit({"schema_version": 1, "session": record, "report": report}, True)
    else:
        print(f"Session {record['id']}  {record['status']}  exit={status}")
        if record["status"] in (
            "denied",
            "backend-unavailable",
            "confirmation-required",
            "cancelled",
            "launch-failed",
        ):
            reason = decision["denials"] or record.get("error")
            if not reason:
                reason = (
                    capability["reason"]
                    if status == 4
                    else "Explicit approval required; use --yes after reviewing permitted risk"
                )
            print("Reason: " + audit.safe(str(reason)))
    return status


def main() -> int:
    args = parser().parse_args()
    try:
        return execute(args)
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError, RuntimeError, TypeError) as exc:
        if getattr(args, "json", False):
            emit({"schema_version": 1, "error": str(exc), "exit_code": 2}, True)
        else:
            print("SafeShell error: " + audit.safe(str(exc)), file=sys.stderr)
        return 2
