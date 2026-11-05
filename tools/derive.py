"""Derive the line-rule, chain, signature and key vectors from vectors/v0-lifecycle.jsonl.

Every vector here is the lifecycle AOF with one deliberate edit, made on bytes.
No verifier and no signing key is involved: an edit either leaves the signed
bytes alone (dropping or reordering whole lines) or breaks exactly one rule.
The output is deterministic, so rerunning must leave the committed files unchanged.

Usage: python3 tools/derive.py <repository-root>
"""

import hashlib
import sys
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64d(text: bytes) -> bytes:
    return urlsafe_b64decode(text + b"=" * (-len(text) % 4))


def b64e(raw: bytes) -> bytes:
    return urlsafe_b64encode(raw).rstrip(b"=")


def member(line: bytes, name: bytes) -> bytes:
    """The raw text of a string member's value. Only used on members without escapes."""
    start = line.index(b'"' + name + b'":"') + len(name) + 4
    return line[start : line.index(b'"', start)]


def replace_once(line: bytes, old: bytes, new: bytes) -> bytes:
    if line.count(old) != 1:
        raise SystemExit(f"expected exactly one {old!r} in the line")
    return line.replace(old, new)


def x_off_curve() -> bytes:
    """The smallest x for which x^3 - 3x + b is not a square mod p: no point has it."""
    x = 1
    while pow((x * x * x - 3 * x + B) % P, (P - 1) // 2, P) == 1:
        x += 1
    return x.to_bytes(32, "big")


def main(root: Path) -> None:
    vectors = root / "vectors"
    l1, l2, l3, l4 = (vectors / "v0-lifecycle.jsonl").read_bytes().split(b"\n")[:4]

    def aof(*lines: bytes) -> bytes:
        return b"".join(line + b"\n" for line in lines)

    signature = b64d(member(l4, b"signature"))
    r, s = signature[:32], int.from_bytes(signature[32:], "big")
    payload_hash = member(l4, b"payload_hash")

    files = {
        "lines/crlf.jsonl": l1 + b"\n" + l2 + b"\r\n" + l3 + b"\n" + l4 + b"\n",
        "lines/no-final-lf.jsonl": aof(l1, l2, l3, l4)[:-1],
        "lines/empty-line.jsonl": l1 + b"\n\n" + aof(l2, l3, l4),
        "lines/duplicate-member.jsonl": aof(l1, l2, l3, b'{"entry_id":"dup",' + l4[1:]),
        "lines/unknown-member.jsonl": aof(l1, l2, l3, b'{"note":"x",' + l4[1:]),
        "lines/non-string-member.jsonl": aof(l1, l2, l3, b'{"v":1,' + l4[1:]),
        "lines/unpaired-surrogate.jsonl": aof(l1, l2, l3, replace_once(l4, b'{"entry_id":"', b'{"entry_id":"\\ud800')),
        "lines/padded-base64.jsonl": aof(l1, l2, l3, replace_once(l4, payload_hash, payload_hash + b"=")),
        "lines/missing-member.jsonl": aof(l1, l2, l3, replace_once(l4, b'"payload_ref":"aof/2026-07/004",', b"")),
        "chain/genesis-nonzero.jsonl": aof(l2, l3, l4),
        "chain/dropped-line.jsonl": aof(l1, l3, l4),
        "chain/reordered.jsonl": aof(l1, l3, l2, l4),
        "signature/altered-entry-id.jsonl": aof(l1, l2, l3, replace_once(l4, b'"entry_id":"evt-004', b'"entry_id":"evt-005')),
        "signature/altered-signature.jsonl": aof(
            l1, l2, l3, replace_once(l4, b64e(signature), b64e(bytes([r[0] ^ 0x01]) + r[1:] + signature[32:]))
        ),
        "signature/negated-s.jsonl": aof(l1, l2, l3, replace_once(l4, b64e(signature), b64e(r + (N - s).to_bytes(32, "big")))),
        "key/off-curve.jsonl": aof(l1, l2, l3, replace_once(l4, member(l4, b"public_key"), b64e(b"\x02" + x_off_curve()))),
    }
    for name, content in files.items():
        path = vectors / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    print(f"wrote {len(files)} vectors; lifecycle line hashes:")
    for line in (l1, l2, l3, l4):
        print(" ", b64e(hashlib.sha256(line).digest()).decode())


main(Path(sys.argv[1]))
