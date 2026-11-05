# conformance

Conformance vectors for the [EventChain protocol](https://eventchain-protocol.github.io/).
Every verifier of the protocol, in any language, reads these files and must
reach the outcome the
[specification](https://eventchain-protocol.github.io/appendix-specification.html)
requires for each.

Verifiers are written independently, from the specification. Agreement on
these vectors is the evidence that they read the format the same way, so no
verifier's own output may decide what a vector's expected outcome is.

## Layout

```
manifest.jsonl         one case per line: the inputs and the outcome the specification requires
vectors/
  v0-lifecycle.jsonl   four base entries under one key, with escapes and non-ASCII text
  mint/                two-line AOFs: a target entry and a Mint entry, sound and broken
  mint/cross/          a WebAuthn assertion from a foreign authenticator, and its generator
  lines/               the lifecycle AOF with one line rule broken
  chain/               the lifecycle AOF with lines dropped or reordered
  signature/           the lifecycle AOF with the last line's signed bytes or signature altered
  key/                 the lifecycle AOF with a public key that names no point
  statement/           Hub-signed heartbeats, a receipt and refusals about the lifecycle AOF
tools/                 the scripts that derived and signed the vectors
```

Each `.jsonl` file under `vectors/` is an AOF. The bytes are the vector: the
chain hashes exact line bytes, so do not reformat, re-encode or re-terminate a
file. `.gitattributes` turns off line-ending conversion for the whole repository.

## Manifest

`manifest.jsonl` holds one JSON object per line. `rule` names the section of
the specification appendix the case rests on, by its anchor.

| `kind` | Inputs | Expected |
|---|---|---|
| `aof` | `aof`: the file | `lines`: the outcome of each line, in order. The list ends at the first `malformed` line, which rejects the file. `mints`: for each Mint whose assertion verified, its `line`, the `target_line` it confirms (`null` when no earlier valid entry has that Event ID) and the `uv`, `be`, `bs` flags. |
| `heartbeat` | `aof`, `heartbeats` (one statement or an array), `hub_key`, `topic_id`, and optionally `now` with `freshness_seconds` | `outcome`, and `covered_position` when a heartbeat was authenticated |
| `statement` | `statement`, `hub_key` | `outcome`: `authentic`, `signature_invalid` or `malformed`; `statement_kind` when authentic |

Line outcomes are the specification's fault names (`malformed`,
`chain_mismatch`, `key_off_curve`, `signature_invalid`, `attestation_fault`)
and `valid` for a line that passed every check.

The manifest is written by reading the specification. No verifier's output
decides an expected outcome, and a verifier that disagrees with a case is a
finding about the verifier or about the specification, to be settled there.

## Open rulings

A case that carries `open` rests on a reading of the specification that its
author has not yet ruled on. The reading is recorded so that verifiers agree
on something; the ruling may change the expected outcome.

| `open` | Reading the manifest takes | What the specification says |
|---|---|---|
| `mint-target` | A Mint whose target is not an earlier valid entry is itself `valid` and confirms nothing (`target_line` is `null`). | "The target must be an earlier verified entry in the same chain", with no outcome named. The Hub's per-line checks cannot see the target, and a refusal and a verifier verdict on one line must agree. |
| `client-data-duplicate` | Client data in which `type` or `challenge` appears twice is an `attestation_fault`: there is no single value to check. | The duplicate-member rule is stated for entries and Hub statements, not for `client_data_json`. |
| `genesis-outcome` | A first entry whose `prev_hash` is not 32 zero bytes is a `chain_mismatch` on line 1. | "A verifier rejects an AOF whose first entry carries any other value", with no outcome named. |
| `high-s` | A signature whose `s` is in the upper half of the range is `valid`. | No low-S rule is stated. |
| `heartbeat-short` | A copy that ends before the entry the latest heartbeat names is reported as `short`. | The mechanism chapter says such a copy "is missing part of the published history"; the appendix names only missing, stale and conflicting. |
| `heartbeat-not-compared` | A copy that is not valid through the covered entry is reported as `not_compared`. | Nothing; the comparison is defined for a verified history. |

Two more names are this repository's, because the specification gives none:
`valid` for a line that passed, and `match` for a copy that agrees with the
latest heartbeat (the mechanism chapter says "report match or deficiency").

## What has no vector yet

Payload commitments (salt and plaintext), registry bindings, OpenTimestamps
proofs, a line with more than one fault, an empty file, and a public key or
base64url value with a non-canonical encoding.

## Using the vectors

Pin this repository by commit, as a git submodule or a fetched archive.
A verifier that tracks a branch can pass today and fail tomorrow without
having changed.

## Provenance

The lifecycle and Mint vectors are the output of the Producer in
[`eventchain-protocol/eventchain`](https://github.com/eventchain-protocol/eventchain),
whose test suite rebuilds them from fixed events and compares the bytes.
`vectors/mint/cross/envelope.json` was produced once by `generate.py` with
soft-webauthn, an implementation that shares nothing with the Producer.

`tools/derive.py` made the `lines`, `chain`, `signature` and `key` vectors
from the lifecycle AOF by byte edits, with no key and no verifier.
`tools/sign_statements.py` signed the `statement` vectors with the OpenSSL
command line under a published test key. Both are deterministic: rerunning
them leaves the committed files unchanged.

## License

[BSD 3-Clause](LICENSE).
