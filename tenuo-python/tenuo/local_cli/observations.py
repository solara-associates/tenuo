"""Read the calls local adapters recorded in observe mode."""

from __future__ import annotations

import json
import shlex
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


MAX_LISTED_VALUES = 5
FREE_TEXT_LEN = 80


def summarize_calls(workspace, *, path=None, tool=None):
    """Per tool: how often it ran, what enforcement would have decided, and what each argument held.

    Deterministic counting over the recorded calls; nothing is inferred or
    suggested beyond the numbers. Draft a warrant from them with warrantgen.
    """
    tools = {}
    runs = set()
    steps = {}
    calls_path = Path(path) if path else workspace.path / OBSERVATIONS
    for call in read_calls(workspace, path):
        if tool is not None and call["tool"] != tool:
            continue
        runs.add(call.get("run"))
        step = call.get("step") or "default"
        steps.setdefault(step, {})[call.get("run")] = call.get("observed_at") or ""
        entry = tools.setdefault(
            call["tool"],
            {
                "calls": 0,
                "runs": set(),
                "would_allow": 0,
                "would_deny": 0,
                "no_warrant": 0,
                "deny_reasons": {},
                "denied_on": {},
                "values": {},
            },
        )
        entry["calls"] += 1
        entry["runs"].add(call.get("run"))
        for name, value in call["args"].items():
            entry["values"].setdefault(name, []).append((call.get("run"), value))
        decision = call.get("decision")
        if decision == "allow":
            entry["would_allow"] += 1
        elif decision == "deny":
            entry["would_deny"] += 1
            reason = call.get("reason") or "denied"
            entry["deny_reasons"][reason] = entry["deny_reasons"].get(reason, 0) + 1
            argument = call.get("argument")
            if isinstance(argument, str) and argument:
                entry["denied_on"][argument] = entry["denied_on"].get(argument, 0) + 1
        else:
            entry["no_warrant"] += 1
    rows = []
    for name, entry in sorted(tools.items(), key=lambda item: (-item[1]["calls"], item[0])):
        row = {"tool": name, "calls": entry["calls"], "runs": len(entry["runs"])}
        for key in ("would_allow", "would_deny", "no_warrant"):
            if entry[key]:
                row[key] = entry[key]
        for key in ("deny_reasons", "denied_on"):
            if entry[key]:
                row[key] = dict(sorted(entry[key].items(), key=lambda item: (-item[1], item[0])))
        row["arguments"] = {arg: _describe(seen) for arg, seen in sorted(entry["values"].items())}
        rows.append(row)
    return {
        "tools": rows,
        "calls": sum(row["calls"] for row in rows),
        "runs": len(runs),
        "next": _next_steps(calls_path, steps),
    }


def _next_steps(calls_path, steps):
    """The exact commands to draft a template per step, from its most recent run."""
    if not steps:
        return ["Run your agent with tenuo-cli mode observe, then run tenuo-cli calls summary again"]
    out = []
    for step, run_times in sorted(steps.items()):
        latest = max(run_times.items(), key=lambda item: (item[1], str(item[0])))[0]
        command = ["warrantgen", "template", str(calls_path), "--step", step]
        if latest is not None:
            command += ["--from-run", str(latest)]
        out.append(" ".join(shlex.quote(part) for part in command + ["--out", f"{step}.yaml"]))
        out.append(f"tenuo-cli template validate --file {shlex.quote(step + '.yaml')}")
        out.append(
            f"tenuo-cli warrant issue --template {shlex.quote(step + '.yaml')} --holder agent"
            f" --out {shlex.quote(step + '.warrant')}"
        )
    out.append("tenuo-cli mode enforce")
    return out


def _describe(seen):
    """What one argument held across calls: distinct values, numeric bounds, and whether runs differ."""
    values = [value for _, value in seen]
    keys = {json.dumps(value, sort_keys=True, default=str) for value in values}
    out = {"distinct": len(keys)}
    by_run = {}
    for run, value in seen:
        by_run.setdefault(run, set()).add(json.dumps(value, sort_keys=True, default=str))
    if len(by_run) > 1:
        out["same_in_every_run"] = len({frozenset(v) for v in by_run.values()}) == 1
    numbers = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if numbers and len(numbers) == len(values):
        out["min"], out["max"] = min(numbers), max(numbers)
    strings = sorted({v for v in values if isinstance(v, str)})
    if strings and len(strings) == len(keys):
        if any(_free_text(v) for v in strings):
            out["free_text"] = True
            return out
        if len(strings) <= MAX_LISTED_VALUES:
            out["values"] = strings
        prefix = _common_prefix(strings)
        if prefix and all("/" in v for v in strings):
            prefix = prefix[: prefix.rfind("/") + 1]  # a shared folder, not part of a name
        if len(strings) > 1 and prefix:
            out["common_prefix"] = prefix
    return out


def _free_text(value):
    """Prose rather than an identifier: whitespace, or long without a path separator."""
    return any(c.isspace() for c in value) or (len(value) > FREE_TEXT_LEN and "/" not in value)


def _common_prefix(strings):
    first, last = strings[0], strings[-1]
    size = 0
    while size < min(len(first), len(last)) and first[size] == last[size]:
        size += 1
    return first[:size]
