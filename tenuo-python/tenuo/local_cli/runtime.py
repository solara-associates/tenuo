"""Read local authority before each protected call, without a signing service."""

from __future__ import annotations

import json
import os
import sys
import threading
import logging
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

from .files import DocumentError, load_yaml, publish, read_revocation_list, write_yaml
from .workspace import Workspace


@dataclass
class Snapshot:
    roots: list
    srl: object
    authorizer: object
    chain: list
    key: object


OBSERVATIONS = "observations.jsonl"
# One run per process unless TENUO_RUN_ID groups calls differently, so every
# adapter in an agent run records the same run for warrantgen.
_PROCESS_RUN = uuid.uuid4().hex


class LocalAuthority:
    """One explicit warrant file, independent public trust, and an agent key.

    The issuer's and approver's private keys are never read here. A malformed
    configured file denies the current call rather than retaining old authority.

    With ``mode: observe`` in the workspace config, adapters block nothing.
    They record each call, with its arguments and the decision enforcement
    would have made, to ``observations.jsonl`` for drafting a warrant.
    """

    def __init__(self, *, path=None, warrant=None, key="agent", announce=True):
        from pathlib import Path

        self.workspace = Workspace(path)
        self.warrant = Path(warrant).expanduser() if warrant is not None else None
        self.key_name = key
        self._last_srl = None
        self._lock = threading.Lock()
        dev = " (development identities)" if self.workspace.config["dev_roots"] else ""
        if self.observing:
            try:
                snapshot = self.snapshot()
                label = str(snapshot.chain[-1].id) if snapshot.chain else "no warrant"
            except Exception as exc:
                label = f"authority unavailable ({_kind(exc)})"
            if announce:
                print(
                    f"Tenuo: observe · {label}{dev} · nothing is blocked · "
                    f"recording calls to {self.observations_path}",
                    file=sys.stderr,
                )
            return
        snapshot = self.snapshot()
        label = str(snapshot.chain[-1].id) if snapshot.chain else "inbound verification"
        if announce:
            print(
                f"Tenuo: enforce · {label} · trusts {len(snapshot.roots)} root(s){dev} · revocations v{snapshot.srl.version}",
                file=sys.stderr,
            )

    @property
    def observing(self):
        """True when the workspace config says ``mode: observe``; reread on every call."""
        return self.workspace.config["mode"] == "observe"

    @property
    def run_id(self):
        """The run calls are recorded under: TENUO_RUN_ID, else one per process."""
        return os.environ.get("TENUO_RUN_ID") or _PROCESS_RUN

    @property
    def observations_path(self):
        return self.workspace.path / OBSERVATIONS

    def require_warrant(self):
        """Enforcement needs a warrant file; observation does not."""
        if self.warrant is None and not self.observing:
            raise DocumentError("mode: enforce needs a warrant; pass warrant=FILE or set mode: observe")

    def decide(self, tool, arguments):
        """The decision enforcement would make for this call, without blocking.

        Returns ``(decision, reason, warrant_id)``: ``decision`` is ``"allow"``,
        ``"deny"``, or ``None`` when there is no warrant to check against. A call
        that needs approval is reported as a denial with reason
        ``approval_required``; no approval request is written.
        """
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import ApprovalRequired

        if self.warrant is None:
            return None, "no_warrant", None
        warrant_id = None
        try:
            snapshot = self.snapshot(verify=False)
            if not snapshot.chain:
                return None, "no_warrant", None
            if snapshot.key is None:
                return None, "no_holder_key", None
            warrant_id = str(snapshot.chain[-1].id)
            snapshot.authorizer.verify_chain(snapshot.chain)
            with self.scope(snapshot) as (current, session, _):
                result = enforce_tool_call(
                    tool_name=tool,
                    tool_args=dict(arguments),
                    bound_warrant=session.bound,
                    trusted_roots=current.roots,
                    warrant_chain=current.chain[:-1],
                    approval_handler=None,
                )
        except ApprovalRequired:
            return "deny", "approval_required", warrant_id
        except Exception as exc:
            return "deny", _kind(exc), warrant_id
        if result.allowed:
            return "allow", None, warrant_id
        return "deny", result.error_type or "denied", warrant_id

    def record(self, tool, arguments, *, decision=None, reason=None, warrant_id=None, run=None, step=None):
        """Append one call to observations.jsonl in warrantgen's trace format.

        Lines carry ``run``, ``step``, ``tool`` and ``args`` as warrantgen reads
        them, plus the observed decision. Argument values are written as given,
        so the file is created readable by its owner only.
        """
        line = {
            "run": run or self.run_id,
            "step": step or "default",
            "tool": tool,
            "args": dict(arguments),
            "decision": decision,
            "reason": reason,
            "warrant_id": warrant_id,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
        data = (json.dumps(line, default=str, allow_nan=False) + "\n").encode()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.observations_path, flags, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        return line

    def observe(self, tool, arguments, *, run=None, step=None):
        """Decide and record one call; never raises for a decision or a record."""
        try:
            decision, reason, warrant_id = self.decide(tool, arguments)
        except Exception as exc:
            decision, reason, warrant_id = None, _kind(exc), None
        try:
            return self.record(
                tool, arguments, decision=decision, reason=reason, warrant_id=warrant_id, run=run, step=step
            )
        except Exception:
            logging.getLogger(__name__).warning("Tenuo observe: could not record a call to %s", tool, exc_info=True)
            return None

    def snapshot(self, verify=True):
        from tenuo import Authorizer
        from .warrants import load_chain

        with self._lock:
            roots = self.workspace.trusted_roots()
            candidate = read_revocation_list(self.workspace.path / "revocations.srl")
            authorizer = Authorizer(trusted_roots=roots)
            authorizer.set_clock_tolerance(0)
            authorizer.set_revocation_list(candidate)
            if self._last_srl is not None:
                # The cached issuer may have been rotated out. It is used only
                # to check the version floor, never as a live warrant root.
                floor = Authorizer(trusted_roots=[*roots, self._last_srl.issuer])
                floor.set_revocation_list(self._last_srl)
                floor.set_revocation_list(candidate)
            self._last_srl = candidate
        chain = load_chain(self.warrant) if self.warrant is not None else []
        if chain and verify:
            authorizer.verify_chain(chain)
        key = self.workspace.signing_key(self.key_name) if self.key_name is not None else None
        if chain and (key is None or bytes(key.public_key.to_bytes()) != bytes(chain[-1].holder_key.to_bytes())):
            raise DocumentError("selected warrant does not match the configured agent key")
        return Snapshot(roots, candidate, authorizer, chain, key)

    def approval_handler(self, snapshot):
        def collect(request):
            return self.collect_file_approval(snapshot.chain, request)

        return collect

    def collect_file_approval(self, chain, request):
        """Return the signed approval for this exact call, or write its request file."""
        from .approvals import request_document, response_approval

        # Verify against current trust and revocations even after a wait.
        current = self.snapshot()
        current.authorizer.verify_chain(list(chain))
        document = request_document(chain, request.tool, request.arguments)
        digest = document["request_hash"]
        if digest != bytes(request.request_hash).hex():
            raise DocumentError("approval request does not match the warrant chain it carries")
        response = self.workspace.path / "approvals" / (digest + ".yaml")
        if response.exists():
            return response_approval(document, load_yaml(response), current.authorizer)
        path = self.workspace.path / "requests" / (digest + ".yaml")
        try:
            write_yaml(path, document)
        except FileExistsError:
            if load_yaml(path) != document:
                raise DocumentError("existing approval request does not match this call") from None
        _pending(
            request,
            f"Approval required for {request.tool}. Review with tenuo-cli approval show --file {path}; "
            f"return the signed response to {response}, then retry.",
        )

    @contextmanager
    def scope(self, snapshot=None):
        from tenuo import HolderIdentity, Runtime
        from tenuo.receipts import FileReceiptSink

        snapshot = self.snapshot() if snapshot is None else snapshot
        if snapshot.key is None:
            yield snapshot, None, None
            return
        runtime = Runtime(
            HolderIdentity(snapshot.key), trusted_roots=snapshot.roots, revocation_list=snapshot.srl, receipts="collect"
        )
        receipt_path = self.workspace.path / self.workspace.config["audit"]["receipts"]
        if not receipt_path.exists():
            try:
                publish(receipt_path, b"")
            except FileExistsError:
                pass
        sink = FileReceiptSink(receipt_path)
        # Receipts don't yet say which mode signed them, so an observed denial
        # would read as an enforced one. Observe mode keeps them out of the file.
        persist = not self.observing
        try:
            with runtime.bind():
                if snapshot.chain:
                    with runtime.session_from_wire(snapshot.chain) as session:
                        yield snapshot, session, self.approval_handler(snapshot)
                else:
                    yield snapshot, None, None
        finally:
            receipts = runtime.drain_receipts()
            try:
                for receipt in receipts if persist else ():
                    sink.handle(receipt)
            except Exception:
                # Never turn a completed effect into a retry because audit I/O
                # failed, or mask an original authorization/tool exception.
                logging.getLogger(__name__).warning("Local receipt persistence failed", exc_info=True)
            else:
                runtime.acknowledge_receipts(len(receipts))


def _kind(exc):
    """A short, value-free label for why a decision could not be made."""
    from tenuo.exceptions import ExpiredError, RevokedError, UntrustedRoot

    for cls, kind in ((ExpiredError, "expired"), (RevokedError, "revoked"), (UntrustedRoot, "untrusted_issuer")):
        if isinstance(exc, cls):
            return kind
    if isinstance(exc, FileNotFoundError):
        return "missing_file"
    return "unavailable:" + type(exc).__name__


def _pending(request, message):
    from tenuo.approval import ApprovalRequired

    try:
        from temporalio import activity
        from temporalio.exceptions import ApplicationError

        in_activity = activity.in_activity()
    except ImportError:
        in_activity = False
    if in_activity:
        # Temporal retries the activity until the response file exists or the
        # warrant expires; no worker slot is held while a person decides.
        raise ApplicationError(message, type="ApprovalPending", non_retryable=False)
    pending = ApprovalRequired(request)
    pending.args = (message,)
    raise pending


def file_approval_handler(path=None):
    """An approval handler that exchanges approval files in a local workspace.

    The handler writes ``requests/<hash>.yaml`` for a gated call and returns the
    signed approval once ``approvals/<hash>.yaml`` holds a response from an
    approver the warrant names (``tenuo-cli approval approve --file ...``). The
    chain travels with each request, so one handler serves every warrant; it is
    checked against the workspace's current trust and revocations. The handler
    reads no private keys.

    While waiting it raises ``ApprovalRequired``, or inside a Temporal activity a
    retryable ``ApplicationError`` of type ``ApprovalPending``.
    """
    authority = LocalAuthority(path=path, key=None, announce=False)

    def handler(request):
        chain = getattr(request, "warrant_chain", None)
        if not chain:
            raise DocumentError("approval request carries no warrant chain, so an approver cannot verify it")
        return authority.collect_file_approval(list(chain), request)

    return handler
