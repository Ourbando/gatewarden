"""Hash-chained decision log and its Ed25519 anchor.

Each record carries the hash of the previous one, so any edit to an earlier record breaks
every hash after it. The head hash is signed. Verification recomputes the whole chain and
checks the signature against a *pinned* public key supplied by the caller, never a key
carried inside the log itself.
"""
from __future__ import annotations

import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _record_hash(record: dict, prev: str) -> str:
    body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
    return hashlib.sha256(canonical(body) + prev.encode()).hexdigest()


def build_chain(entries: list[dict]) -> list[dict]:
    """Turn a list of entries into a hash-chained list of records."""
    chain: list[dict] = []
    prev = ""
    for i, entry in enumerate(entries):
        record = {"seq": i, "prev": prev, **entry}
        record["hash"] = _record_hash(record, prev)
        chain.append(record)
        prev = record["hash"]
    return chain


def head_hash(chain: list[dict]) -> str:
    return chain[-1]["hash"] if chain else ""


def sign_head(chain: list[dict], private_key: Ed25519PrivateKey) -> str:
    return private_key.sign(head_hash(chain).encode()).hex()


def verify_chain(
    chain: list[dict], signature_hex: str, public_key: Ed25519PublicKey
) -> tuple[bool, str]:
    prev = ""
    for i, record in enumerate(chain):
        if record.get("seq") != i:
            return False, f"chain order broken at index {i}"
        if record.get("prev") != prev:
            return False, f"chain link broken at seq {i}"
        if record.get("hash") != _record_hash(record, prev):
            return False, f"hash mismatch at seq {i} (record was altered)"
        prev = record["hash"]
    try:
        public_key.verify(bytes.fromhex(signature_hex), prev.encode())
    except Exception:
        return False, "signature does not verify against the pinned key"
    return True, "ok"


def new_key(private_path: str) -> Ed25519PrivateKey:
    """Generate a keypair, write the private PEM to ``private_path`` and the public PEM
    beside it (``.pub``). Returns the private key."""
    os.makedirs(os.path.dirname(private_path) or ".", exist_ok=True)
    key = Ed25519PrivateKey.generate()
    with open(private_path, "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    with open(os.path.splitext(private_path)[0] + ".pub", "wb") as fh:
        fh.write(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return key


def load_private(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def load_public(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as fh:
        return serialization.load_pem_public_key(fh.read())
