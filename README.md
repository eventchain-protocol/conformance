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
vectors/
  v0-lifecycle.jsonl   four base entries under one key, with escapes and non-ASCII text
  mint/                two-line AOFs: a target entry and a Mint entry, sound and broken
  mint/cross/          a WebAuthn assertion from a foreign authenticator, and its generator
```

Each `.jsonl` file is an AOF. The bytes are the vector: the chain hashes exact
line bytes, so do not reformat, re-encode or re-terminate a file.
`.gitattributes` turns off line-ending conversion for the whole repository.

## Status

The expected outcome of each vector is not yet recorded here. A manifest
stating, per vector, the outcome the specification requires will be added
once the specification's outcome vocabulary is settled. The vectors cover
entries and Mint envelopes only; heartbeats, receipts, refusals and most
line-rule faults have no vector yet.

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

## License

[BSD 3-Clause](LICENSE).
