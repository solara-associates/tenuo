# AAT JWS vector interop

Results of running the AAT JWS test vectors
([`../../tests/vectors/aat-jws-vectors.json`](../../tests/vectors/aat-jws-vectors.json))
against implementations of `draft-niyikiza-oauth-attenuating-agent-tokens`.
An implementation is listed here only with its maintainers' agreement.

## Running the suite

For each vector, verify `chain_compact` and `pop.compact` as Section 8
describes, for the invocation `tool` with the arguments in `args_json`, at the
time `now`. The suite-level `trust_anchors` and `params` apply to every vector;
a vector's own `params` and `policy` override them, and `replay_state.before`
is the accepted PoP `jti` set when a vector tracks replay. Read `args_json`
and each token's `payload_json` with a parser that keeps a number's exact
value; [`README.md`](README.md) lists the conventions.

Record each verdict by vector id, as a JSON object:

```json
{"J.1": "PERMIT", "J.2": {"verdict": "DENY", "step": "2c"}}
```

A vector your implementation does not support can be `"SKIP"`, with an
optional `"reason"`. Then compare:

```bash
python3 ietf/vectors/compare_results.py results.json
```

It prints the suite's SHA-256, so a report names the exact bytes it ran
against, then the count of agreements and every disagreement. Only verdicts
are compared: Section 8 permits some reordering, so a different failing step
is not a disagreement (`--steps` lists them).

## Reporting

Open an issue or a pull request with the comparison output, and say:

- the implementation's name, language, version, and license;
- whether we may list it here and in the draft's Implementation Status
  section.

Each disagreement is either a bug on one side or an ambiguity in the draft.
Please report both; ambiguities are fixed in the draft.

## Results

| Implementation | Language | Version | Suite SHA-256 | Agree | Skipped | Notes |
|---|---|---|---|---|---|---|
| `gen_vectors.py` self-check | Python | this repository | `ef053277e87c467c…` | 224 / 224 | 0 | Generates the suite; its Section 8 verifier shares no code with Tenuo. |
