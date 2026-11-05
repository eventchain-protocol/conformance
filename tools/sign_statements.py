"""Sign the Hub-statement vectors (heartbeats, a receipt, refusals) with the OpenSSL command line.

The statements describe vectors/v0-lifecycle.jsonl under the topic "demo". They
are signed by a test key whose private scalar is published below, so the files
can be rebuilt byte for byte: OpenSSL 3.2 or later signs deterministically
(RFC 6979) with nonce-type 1. The key protects nothing.

The signed message is the RFC 8785 serialisation of the statement's members
without `signature`. Every member here is an ASCII string, so sorted keys and
compact separators give exactly that.

Usage: python3 tools/sign_statements.py <repository-root> [path-to-openssl]
"""

import hashlib
import json
import subprocess
import sys
import tempfile
from base64 import urlsafe_b64encode
from pathlib import Path

HUB_SCALAR = hashlib.sha256(b"eventchain conformance: hub test key").digest()
OTHER_SCALAR = hashlib.sha256(b"eventchain conformance: a key the topic does not accept").digest()
TOPIC = "demo"


def b64e(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode()


def sec1_private_key(scalar: bytes) -> bytes:
    """DER ECPrivateKey for P-256 holding only the scalar and the curve name."""
    return bytes.fromhex("30310201010420") + scalar + bytes.fromhex("a00a06082a8648ce3d030107")


def der_integers(der: bytes) -> tuple[int, int]:
    """r and s from a DER ECDSA-Sig-Value with short-form lengths (always the case for P-256)."""
    assert der[0] == 0x30 and der[2] == 0x02
    r_len = der[3]
    r = int.from_bytes(der[4 : 4 + r_len], "big")
    assert der[4 + r_len] == 0x02
    s_len = der[5 + r_len]
    s = int.from_bytes(der[6 + r_len : 6 + r_len + s_len], "big")
    return r, s


class Signer:
    def __init__(self, openssl: str, scalar: bytes, workdir: Path):
        self.openssl = openssl
        self.workdir = workdir
        self.key_path = workdir / (hashlib.sha256(scalar).hexdigest()[:8] + ".der")
        self.key_path.write_bytes(sec1_private_key(scalar))

    def public_key(self) -> str:
        spki = subprocess.run(
            [self.openssl, "ec", "-inform", "DER", "-in", str(self.key_path), "-pubout", "-conv_form", "compressed", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        return b64e(spki[-33:])

    def sign(self, members: dict[str, str]) -> dict[str, str]:
        message = json.dumps(members, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        message_path = self.workdir / "message"
        message_path.write_bytes(message)
        der = subprocess.run(
            [self.openssl, "dgst", "-sha256", "-sign", str(self.key_path), "-keyform", "DER", "-sigopt", "nonce-type:1", str(message_path)],
            check=True,
            capture_output=True,
        ).stdout
        r, s = der_integers(der)
        return {**members, "signature": b64e(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}


def main(root: Path, openssl: str) -> None:
    out = root / "vectors" / "statement"
    out.mkdir(parents=True, exist_ok=True)
    lines = (root / "vectors" / "v0-lifecycle.jsonl").read_bytes().split(b"\n")[:4]
    head = [b64e(hashlib.sha256(line).digest()) for line in lines]
    absent = b64e(hashlib.sha256(b"an entry this history does not contain").digest())

    with tempfile.TemporaryDirectory() as tmp:
        hub = Signer(openssl, HUB_SCALAR, Path(tmp))
        other = Signer(openssl, OTHER_SCALAR, Path(tmp))

        def heartbeat(position: str, head_hash: str, issued_at: str, **extra: str) -> dict[str, str]:
            return hub.sign({"v": "1", "kind": "heartbeat", "topic_id": TOPIC, "position": position, "head_hash": head_hash, "issued_at": issued_at, **extra})

        at_2 = heartbeat("2", head[1], "1789999000")
        at_4 = heartbeat("4", head[3], "1790000000")
        at_4_other_head = heartbeat("4", head[2], "1790000000")
        statements: dict[str, object] = {
            "heartbeat-at-2.json": at_2,
            "heartbeat-at-4.json": at_4,
            "heartbeat-at-4-other-head.json": at_4_other_head,
            "heartbeat-at-5.json": heartbeat("5", absent, "1790000000"),
            "heartbeat-fraction.json": heartbeat("4", head[3], "1790000000.5"),
            "heartbeat-leading-zero.json": heartbeat("04", head[3], "1790000000"),
            "heartbeat-trailing-zero.json": heartbeat("4", head[3], "1790000000.50"),
            "heartbeat-unknown-member.json": heartbeat("4", head[3], "1790000000", note="x"),
            "heartbeat-list.json": [at_2, at_4],
            "heartbeat-list-conflicting.json": [at_4, at_4_other_head],
            "receipt.json": hub.sign(
                {"v": "1", "kind": "receipt", "topic_id": TOPIC, "submission_hash": head[3], "issued_at": "1790000000", "position": "4", "head_hash": head[3], "count": "1"}
            ),
            "refusal-head-mismatch.json": hub.sign(
                {"v": "1", "kind": "refusal", "topic_id": TOPIC, "submission_hash": absent, "issued_at": "1790000000", "reason": "head_mismatch", "position": "4", "head_hash": head[3]}
            ),
            "refusal-line.json": hub.sign(
                {"v": "1", "kind": "refusal", "topic_id": TOPIC, "submission_hash": absent, "issued_at": "1790000000", "reason": "signature_invalid", "line": "1"}
            ),
        }
        for name, statement in statements.items():
            (out / name).write_bytes(json.dumps(statement, separators=(",", ":"), ensure_ascii=False).encode())
        print(json.dumps({"hub_key": hub.public_key(), "other_key": other.public_key(), "files": len(statements)}, separators=(",", ":")))


main(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else "openssl")
