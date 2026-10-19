"""Warrant review: plain-language authority and attack inputs that get through."""

import json
from pathlib import Path

import pytest
import yaml

from tenuo import SigningKey, WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.review import probes, kind, review_chain, review_template
from tenuo.local_cli.workspace import Workspace

LOOSE = {
    "version": 2,
    "ttl": "8h",
    "capabilities": {
        "read_file": {"path": {"pattern": "src/*"}},
        "write_file": {"path": {"regex": "src/"}, "content": "any"},
        "run_command": {"cmd": "any"},
        "fetch": {"url": {"url_pattern": "https://*"}},
        "refund": {"order_id": "any", "amount_cents": "1.."},
    },
}


def tight(root):
    return {
        "version": 2,
        "ttl": "30m",
        "capabilities": {
            "read_file": {"path": {"subpath": str(root)}},
            "write_file": {"path": {"subpath": str(root)}, "content": "any"},
            "run_command": {"cmd": ["pytest", "git status"]},
            "fetch": {"url": {"url_pattern": "https://docs.python.org/3/*"}},
            "search": {"query": "any"},
            "refund": {"order_id": "A-1001", "amount_cents": "1..12000"},
        },
    }


def by_place(result):
    return {(f.get("tool"), f.get("argument")): f for f in result["findings"]}


def test_loose_template_reports_what_gets_through():
    result = review_template(WarrantTemplate(LOOSE))
    found = by_place(result)
    assert "src/../.env" in found["read_file", "path"]["allowed_inputs"]
    assert "/tmp/elsewhere/src/x" in found["write_file", "path"]["allowed_inputs"]
    assert "cat ~/.tenuo/keys/issuer.key" in found["run_command", "cmd"]["allowed_inputs"]
    assert found["fetch", "url"]["problem"].startswith('"https://*" matches no URL')
    assert found["refund", "amount_cents"]["severity"] == "high"
    assert found["refund", None]["problem"] == "Runs without approval."
    assert found[None, None]["problem"] == "Valid for 8h."
    assert ("write_file", "content") not in found
    assert [f["severity"] for f in result["findings"]] == sorted(
        (f["severity"] for f in result["findings"]), key=["high", "medium", "low"].index
    )


def test_tight_template_has_no_findings(tmp_path):
    result = review_template(WarrantTemplate(tight(tmp_path)))
    assert [(f["tool"], f["problem"]) for f in result["findings"]] == [("refund", "Runs without approval.")]
    assert result["allows"]["run_command"]["cmd"] == "one of: pytest, git status"
    assert result["allows"]["refund"]["amount_cents"] == "1 to 12000"


@pytest.mark.parametrize("document", [LOOSE, None])
def test_allowed_inputs_match_the_issued_warrant(tmp_path, document):
    """Every reported input is allowed by the real verifier check; every other probe is denied."""
    document = document or tight(tmp_path)
    template = WarrantTemplate(document)
    warrant = template.mint(SigningKey.generate(), SigningKey.generate().public_key)
    reported = {
        (f.get("tool"), f.get("argument")): set(f.get("allowed_inputs", []))
        for f in review_chain([warrant])["findings"]
    }
    for tool, arguments in template._capabilities.items():
        if len(arguments) != 1:
            continue
        ((argument, constraint),) = arguments.items()
        for value in probes(constraint, kind(argument, tool)):
            allowed = warrant.check_constraints(tool, {argument: value}) is None
            assert allowed == (value in reported.get((tool, argument), set())), (tool, value)


def test_argument_kinds():
    assert kind("file_path") == "path"
    assert kind("amount_cents") == "money"
    assert kind("webhook_url") == "url"
    assert kind("body") == "text"
    assert kind("order_id") == "value"
    assert kind("query") == "text"
    assert kind("query", tool="run_sql") == "command"


def test_home_directory_subpath_and_sql_query():
    root = {
        "version": 2,
        "ttl": "30m",
        "capabilities": {
            "read_file": {"path": {"subpath": str(Path.home())}},
            "run_sql": {"query": "any"},
        },
    }
    found = by_place(review_template(WarrantTemplate(root)))
    assert found["read_file", "path"]["problem"].startswith("This directory contains secrets")
    assert str(Path.home() / ".ssh" / "id_rsa") in found["read_file", "path"]["allowed_inputs"]
    assert found["run_sql", "query"]["severity"] == "high"


@pytest.fixture
def workspace(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(LOOSE))
    return workspace, path


def test_cli_validate_issue_and_review(workspace, capsys):
    workspace, path = workspace
    prefix = ["--home", str(workspace.path), "--json"]
    assert main([*prefix, "template", "validate", "--file", str(path)]) == 0
    brief = json.loads(capsys.readouterr().out)["review"]
    assert brief["summary"].startswith("5 tools, valid for 8h: 4 high, 2 medium")
    assert any('Gets through: "src/../.env"' in line for line in brief["findings"])
    assert brief["details"] == f"tenuo-cli warrant review --file {path}"

    out = path.parent / "agent.warrant"
    assert main([*prefix, "warrant", "issue", "--template", str(path), "--holder", "agent", "--out", str(out)]) == 0
    issued = json.loads(capsys.readouterr().out)
    assert issued["review"]["summary"].startswith("5 tools, expires in")
    assert issued["review"]["details"] == f"tenuo-cli warrant review --file {out}"

    assert main([*prefix, "warrant", "review", "--file", str(out)]) == 0
    full = json.loads(capsys.readouterr().out)["review"]
    assert full["subject"] == "warrant" and full["id"] == issued["warrant"]["id"]
    assert full["delegation"] == "can delegate narrower copies"
    assert main([*prefix, "warrant", "review", "--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["review"]["subject"] == "template"


def test_cli_review_needs_no_workspace(tmp_path, capsys):
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(tight(tmp_path)))
    assert main(["--home", str(tmp_path / "missing"), "--json", "warrant", "review", "--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["review"]["summary"] == "6 tools, valid for 30m: 1 low"
