---
title: Tenuo on the Temporal Agent Harness
description: From the refunds demo to your own agent on the Temporal agent harness, with each tool call checked against a warrant
---

# Tenuo on the Temporal Agent Harness

The [Temporal agent harness](https://github.com/temporal-community/temporal-agent-harness) runs
AI agents as Temporal workflows: each chat session is a workflow, each tool call is an activity,
and the harness gives you a chat UI, approvals and replay on top. Its auto mode decides tool calls
without asking a person, and Tenuo can be the thing that decides. Each session carries a warrant,
and every tool call is checked against it: which tools, which arguments, how much, and whose
approval it needs.

This page starts where the harness's `tenuo_refunds` example ends. If you haven't run it yet, do
that first. It takes one command:

```sh
cd python/examples/tenuo_refunds
just demo
```

You'll see a $30 refund run on its own, a $60 refund wait for the support lead's approval, and a
refund on someone else's order denied. The rest of this page takes you from there to your own
agent, one working step at a time.

## Temporal in five terms

You don't need to know Temporal to follow this page. These are the terms it uses:

| Term | In the refunds example |
|---|---|
| **Workflow** | One chat session. Temporal records everything it does, so it survives restarts. |
| **Activity** | One tool call, like `refund`. Temporal retries it if it fails. |
| **Worker** | Your process (`worker.py`). It runs the workflows and activities, and it's where Tenuo checks each call. |
| **Task queue** | How Temporal finds your worker: the session's agent names a queue, and your worker polls it. |
| **Temporal server** | Keeps the history. `just temporal` runs one locally; in production it's Temporal Cloud or your own cluster. |

When you want more, Temporal's
[getting started guides](https://learn.temporal.io/getting_started/) go deeper.

## 1. Change what the agent may do

The warrant is the agent's policy, and it lives outside the agent. In the example it's built in
`issue_warrant.py`:

```python
#: Refunds up to this many cents run without asking anyone.
AUTONOMOUS_REFUND_CENTS = 5000

def issue(order_id: str) -> Warrant:
    order = ORDERS[order_id]
    return (
        Warrant.mint_builder()
        .capability("get_order", order_id=Exact(order_id))
        .capability("refund", order_id=Exact(order_id), amount_cents=Range(1, order["total_cents"]))
        .approval_gates({"refund": {"amount_cents": {"exempt": Range(1, AUTONOMOUS_REFUND_CENTS)}}})
        .required_approvers([keys.approver().public_key])
        .min_approvals(1)
        .holder(keys.holder().public_key)
        .ttl(TTL_SECONDS)
        .mint(keys.root())
    )
```

Set `AUTONOMOUS_REFUND_CENTS = 10000` and start a new session with `just session A-1001`. The $60
refund now runs without asking. You didn't change the agent, its prompt or its tools, and the
sessions you started earlier keep the warrant they started with.

A few more to try:

- Cap every refund at $75: `amount_cents=Range(1, 7500)`. A $90 request is denied, approval or not.
- Need the support lead for every refund: gate it outright with `.approval_gates({"refund": None})`.
- Shorten the session: `TTL_SECONDS = 600`. After ten minutes, every call is denied.

The [constraints reference](./constraints.md) lists every constraint you can put on an argument,
and [Human Approvals](./approvals.md) covers gates and multi-approver thresholds.

## 2. Add your own tool

Say the agent should be able to offer store credit. Add the tool in `tools.py`:

```python
@agent.activity_tool_defn()
async def store_credit(order_id: str, amount_cents: int) -> str:
    """Give the customer store credit on an order. `amount_cents` is in cents."""
    return f"Issued ${amount_cents / 100:.2f} store credit on {order_id}."

ALL_TOOLS = [get_order, refund, store_credit]
```

Give it to the agent in `workflow.py`: import it, and add it next to the other two.

```python
from examples.tenuo_refunds.tools import get_order, refund, store_credit
```

```python
tools=[
    as_openai_agent_tool(self._runner, get_order),
    as_openai_agent_tool(self._runner, refund),
    as_openai_agent_tool(self._runner, store_credit),
],
```

Restart the worker, start a session and ask for $20 in store credit. It's **denied**: the agent has
the tool, but the warrant doesn't. Tools the warrant doesn't name never run. Now add it to the
warrant in `issue_warrant.py`:

```python
.capability("store_credit", order_id=Exact(order_id), amount_cents=Range(1, 2500))
```

Start a new session, and the same request runs. Up to $25 of store credit, on this order only,
with no change to how the agent was built.

That's the loop for every tool you add: write the activity, give it to the agent, and decide in
the warrant how far it may go.

## 3. Issue warrants from your app

In the example, `just session` plays your support platform. In your app, the same thing happens
when work arrives: a ticket is opened, so you issue a warrant for that ticket's order and start a
session with it.

```python
import httpx
from tenuo import Exact, Range, Warrant

def start_refund_session(ticket, issuer_key, agent_key, approver_key) -> str:
    """Start an agent session scoped to one support ticket. Returns the session ID."""
    warrant = (
        Warrant.mint_builder()
        .capability("get_order", order_id=Exact(ticket.order_id))
        .capability("refund", order_id=Exact(ticket.order_id), amount_cents=Range(1, ticket.order_total_cents))
        .approval_gates({"refund": {"amount_cents": {"exempt": Range(1, 5000)}}})
        .required_approvers([approver_key])
        .min_approvals(1)
        .holder(agent_key)
        .ttl(3600)
        .mint(issuer_key)
    )
    response = httpx.post(
        f"{HARNESS_URL}/api/sessions",
        json={
            "agent_workflow_type": "TenuoRefundsAgent",
            # One session per ticket: creating it again returns the same session.
            "session_id": f"refund-{ticket.id}",
            "data": {"warrant": warrant.to_base64()},
        },
    )
    response.raise_for_status()
    return response.json()["workflow_id"]
```

`issuer_key` is a `SigningKey` and the other two are public keys. Three keys, three owners:

- **The issuer key** signs warrants. Only the service that runs this code holds it, ideally from
  your secrets manager. The agent's worker never sees it.
- **The agent key** is the holder the warrant is issued to. The worker holds it and proves
  possession on every call, so a warrant copied out of a session is useless without it.
- **The approver keys** belong to the people the warrant names. See the next step.

The worker only needs to trust the issuer's public key (`trusted_roots` in its
`TenuoPluginConfig`), so you can issue warrants from as many places as you like without
redeploying it.

## 4. Move approvals to the approvers

In the example the worker holds the support lead's key and asks in its own output. That's fine on
your laptop, but in production the approver's key should stay with the approver: whoever holds it
can approve anything the warrant gates.

The worker's `approval_handler` is where that changes. It receives the exact call waiting for
approval, and returns the approver's signature or raises `ApprovalDenied`. Keep the worker's
config the same and swap the handler:

- **Your own channel.** Write a handler that asks wherever your approvers already work and returns
  their signature. [Custom Handlers](./approvals.md#custom-handlers) shows the shape.
- **Tenuo Cloud.** Approvals reach approvers in the dashboard or Slack, signed with keys bound to
  their identity, so you don't build or run the handler yourself.

Either way, the evaluator checks the signature against the warrant before the call runs: the right
approver, this exact call with these arguments, not expired. An approval for $60 can't be reused
for $90.

While a call waits, the harness's own UI also shows it as pending approval, with its own approve
buttons. A click there isn't signed by anyone the warrant names, so don't give the harness's
approval controls to people who aren't approvers.

## 5. Go to production

When the agent works locally, these are the changes that matter:

1. **Temporal connection.** Point the worker and the harness at Temporal Cloud or your cluster
   with a connection profile (`TEMPORAL_CONFIG_FILE` and `TEMPORAL_PROFILE` in `.env.local`).
   Nothing Tenuo-specific changes.
2. **Keys.** The issuer key lives with the service that issues warrants; the agent key lives with
   the worker, loaded before the worker starts; approver keys live with approvers.
3. **Warrant lifetimes.** Match the TTL to the task. A refund ticket needs an hour, not a week.
   Long-running sessions can be given a fresh warrant rather than a long one.
4. **Issuer rotation.** When you replace the issuer key, list both public keys in the worker's
   `trusted_roots` until the old key's warrants have expired, then drop the old one.
5. **Everything else in the Temporal integration's
   [path to production](./temporal-reference.md#path-to-production)**, which applies to harness
   workers too.

## See also

- [Temporal Integration](./temporal.md): Tenuo's Temporal plugin, for workflows outside the harness.
- [Temporal Quickstart](./temporal-quickstart.md): one authorized workflow, no agent, in a few minutes.
- [Human Approvals](./approvals.md): gates, thresholds and handlers.
- [Constraints](./constraints.md): every way to limit an argument.
