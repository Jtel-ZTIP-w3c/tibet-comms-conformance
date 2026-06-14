"""Deterministic Ed25519 for the SIGNED comms levels (v5 I-Poll, v7 sealed Cmail).

Fixed seeds -> reproducible keys, public keys, and signatures, fully offline. Ed25519 is
deterministic (RFC 8032): the same seed over the same canonical string yields a byte-identical
signature, so a second implementation that signs the SAME canonical with the SAME seed gets the
SAME bytes. The canonical builders below are the contract — sign and verify over these exact
strings, nothing else.

This mirrors how `ztip-conformance` derives its keys, so the two kits share one crypto idiom.
"""

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _seed(actor: str) -> bytes:
    # 32-byte Ed25519 seed, one per actor, derived from a fixed namespace + the actor id.
    return hashlib.sha256(b"tibet-comms-conformance/actor/v1:" + actor.encode("utf-8")).digest()


def _sk(actor: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_seed(actor))


def pub_b64(actor: str) -> str:
    raw = _sk(actor).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def sign_b64(actor: str, canonical: str) -> str:
    return base64.b64encode(_sk(actor).sign(canonical.encode("utf-8"))).decode("ascii")


def verify_b64(pub_b64_str: str, sig_b64: str, canonical: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64_str)).verify(
            base64.b64decode(sig_b64), canonical.encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# --- Canonical strings (the contract). Sign/verify over exactly these. ---

def ipoll_canonical(m: dict) -> str:
    return (
        "ipoll:v1:"
        f"{m['kind']}:{m['message_id']}:{m['from_actor']}:{m['to_aint']}:{m.get('ack_for', '')}"
    )


def sealed_canonical(c: dict) -> str:
    return f"tza.sealed:v1:{c['content_hash']}:{c['continuity_state']}"


def sendpath_canonical(actor_id: str, name: str, endpoint: str) -> str:
    # The actor signs the binding of its identity to a named .aint route + endpoint, so the
    # send-path is bound by possession of the key, not by a string lookup anyone can fake.
    return f"ains-sendpath:v2:{actor_id}:{name}:{endpoint}"
