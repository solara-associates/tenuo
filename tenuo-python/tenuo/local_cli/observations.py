"""Read the calls local adapters recorded in observe mode."""

from __future__ import annotations

import json
from pathlib import Path

from .files import DocumentError
from .runtime import OBSERVATIONS

MAX_OBSERVATION_BYTES = 64 * 1024 * 1024


def read_calls(workspace, path=None):
    path = Path(path) if path else workspace.path / OBSERVATIONS
    if not path.exists():
        return []
    with path.open("rb") as stream:
        raw = stream.read(MAX_OBSERVATION_BYTES + 1)
    if len(raw) > MAX_OBSERVATION_BYTES:
        raise DocumentError("observations exceed 64 MiB; move the file aside and pass it with --file")
    calls = []
    for number, line in enumerate(raw.decode().splitlines(), 1):
        if not line.strip():
            continue
        try:
            call = json.loads(line)
        except ValueError:
            raise DocumentError(f"{path}:{number}: not a JSON line") from None
        if (
            not isinstance(call, dict)
            or not isinstance(call.get("tool"), str)
            or not isinstance(call.get("args"), dict)
        ):
            raise DocumentError(f"{path}:{number}: expected a recorded call with tool and args")
        calls.append(call)
    return calls


def list_calls(workspace, *, path=None, tool=None, limit=100):
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise DocumentError("limit must be between 1 and 10000")
    calls = [call for call in read_calls(workspace, path) if tool is None or call["tool"] == tool]
    return {"calls": calls[-limit:], "matching_calls": len(calls)}


def summarize_calls(workspace, *, path=None, tool=None):
    """Per tool: how often it ran, what enforcement would have decided, and its argument names."""
    tools = {}
    runs = set()
    for call in read_calls(workspace, path):
        if tool is not None and call["tool"] != tool:
            continue
        runs.add(call.get("run"))
        entry = tools.setdefault(
            call["tool"],
            {"calls": 0, "would_allow": 0, "would_deny": 0, "no_warrant": 0, "arguments": set(), "deny_reasons": {}},
        )
        entry["calls"] += 1
        entry["arguments"].update(call["args"])
        decision = call.get("decision")
        if decision == "allow":
            entry["would_allow"] += 1
        elif decision == "deny":
            entry["would_deny"] += 1
            reason = call.get("reason") or "denied"
            entry["deny_reasons"][reason] = entry["deny_reasons"].get(reason, 0) + 1
        else:
            entry["no_warrant"] += 1
    rows = []
    for name, entry in sorted(tools.items(), key=lambda item: -item[1]["calls"]):
        row = {"tool": name, **entry, "arguments": sorted(entry["arguments"])}
        if not row["deny_reasons"]:
            del row["deny_reasons"]
        rows.append(row)
    return {
        "tools": rows,
        "calls": sum(row["calls"] for row in rows),
        "runs": len(runs),
        "next": "Draft a warrant from these calls with warrantgen, then run tenuo-cli mode enforce",
    }
