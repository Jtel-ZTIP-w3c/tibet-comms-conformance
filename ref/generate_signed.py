#!/usr/bin/env python3
"""Regenerate the SIGNED comms vectors (v5 I-Poll, v7 sealed Cmail) with real Ed25519.

Deterministic + offline: re-running this produces byte-identical vectors (same seed, same
canonical, same signature). It preserves the existing logical cases, stamps each envelope/carrier
with a real `*_pubkey` + `signature`, and appends a `bad-signature` negative case whose signature
is valid base64 but signed over a different canonical, so it must fail verification.

Run from the repo root or ref/:  python3 ref/generate_signed.py
"""

import json
from pathlib import Path

from _crypto import ipoll_canonical, pub_b64, sealed_canonical, sign_b64

VEC = Path(__file__).resolve().parents[1] / "vectors"


def _write(path: Path, doc: dict, indent: int) -> None:
    path.write_text(json.dumps(doc, indent=indent) + "\n", encoding="utf-8")


def gen_ipoll() -> None:
    path = VEC / "ipoll_v5.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    cases = [c for c in doc["cases"] if c["name"] != "bad-signature"]
    for c in cases:
        m = c["message"]
        actor = m["from_actor"]
        m["from_pubkey"] = pub_b64(actor)
        m["signature"] = sign_b64(actor, ipoll_canonical(m))

    # bad-signature: structurally valid PUSH, but the signature is over a TAMPERED canonical
    # (different message_id), so it is a real, well-formed signature that simply does not match.
    bad = {
        "kind": "PUSH",
        "message_id": "msg-badsig",
        "from_actor": "jis:agent:alice",
        "to_aint": "bob.aint",
    }
    bad["from_pubkey"] = pub_b64("jis:agent:alice")
    tampered = dict(bad, message_id="msg-tampered")
    bad["signature"] = sign_b64("jis:agent:alice", ipoll_canonical(tampered))
    cases.append({"name": "bad-signature", "message": bad, "expect_deliver": False})

    doc["cases"] = cases
    doc["rule"] = (
        "deliver := kind in PUSH|PULL|SYNC|TASK|ACK AND from_actor starts 'jis:' AND to_aint "
        "ends '.aint' AND message_id unseen AND (ACK => ack_for delivered) AND signature verifies "
        "over ipoll:v1:<kind>:<message_id>:<from_actor>:<to_aint>:<ack_for> under from_pubkey"
    )
    _write(path, doc, indent=1)
    print(f"signed {len(cases)} ipoll cases -> {path.name}")


def gen_sealed() -> None:
    path = VEC / "sealed_cmail_v7.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    cases = [c for c in doc["cases"] if c["name"] != "bad-signature"]
    sealer = "jis:agent:sealer"
    for c in cases:
        carrier = c["carrier"]
        carrier["sealer"] = sealer
        carrier["sealer_pubkey"] = pub_b64(sealer)
        carrier["signature"] = sign_b64(sealer, sealed_canonical(carrier))

    # bad-signature: a sealed carrier that would otherwise accept, but its signature is over a
    # tampered canonical (different content_hash) -> must quarantine.
    good_carrier = {
        "carrier_kind": "tza.sealed.v1",
        "sealed_payload": "hello sealed world",
        "content_hash": "sha256:6a5063771a9b7d07d2a3be0b2101b1ffe9d3eb02b0e8605590d86086d4958c18",
        "continuity_state": "arrived",
        "sealer": sealer,
        "sealer_pubkey": pub_b64(sealer),
    }
    tampered = dict(good_carrier, content_hash="sha256:deadbeef")
    good_carrier["signature"] = sign_b64(sealer, sealed_canonical(tampered))
    cases.append({"name": "bad-signature", "carrier": good_carrier, "expect_decision": "quarantine"})

    doc["cases"] = cases
    doc["rule"] = (
        "accept := carrier_kind == 'tza.sealed.v1' AND sha256(sealed_payload) == content_hash AND "
        "continuity_state in {arrived,verified} AND signature verifies over "
        "tza.sealed:v1:<content_hash>:<continuity_state> under sealer_pubkey; else quarantine"
    )
    _write(path, doc, indent=2)
    print(f"signed {len(cases)} sealed cases -> {path.name}")


if __name__ == "__main__":
    gen_ipoll()
    gen_sealed()
