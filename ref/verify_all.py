#!/usr/bin/env python3
"""Reference verifier for the sandbox TIBET comms vectors.

This proves only that the reference runner agrees with the vectors. It is not an interop
proof. A real implementation should consume vectors/*.json and reproduce the same verdicts
without importing this file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from _crypto import ipoll_canonical, sealed_canonical, sendpath_canonical, verify_b64


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors"


def load(name: str) -> dict:
    with (VECTORS / name).open(encoding="utf-8") as f:
        return json.load(f)


def ssm_ok(surface: str) -> bool:
    return isinstance(surface, str) and len(surface.split(".")) == 4 and all(surface.split("."))


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_ping() -> tuple[int, int]:
    doc = load("ping_v1.json")
    now = doc["verify_at"]
    ok = total = 0
    print("### v1 - ping frame")
    for c in doc["cases"]:
        total += 1
        if not str(c["actor_id"]).startswith("jis:"):
            got = "BAD_ACTOR"
        elif not ssm_ok(c["surface"]):
            got = "BAD_SURFACE"
        elif now >= c["issued_at"] + c["ttl_seconds"]:
            got = "STALE"
        elif not c["nonce"]:
            got = "BAD_NONCE"
        else:
            got = "ALIVE"
        passed = got == c["expect_status"]
        ok += int(passed)
        print_case(passed, c["name"], got, c["expect_status"])
    return ok, total


def verify_sendpath() -> tuple[int, int]:
    doc = load("sendpath_v2.json")
    ok = total = 0
    print("### v2 - AINS sendpath")
    for c in doc["cases"]:
        total += 1
        r = c.get("record") or {}
        route = c.get("route") or {}
        endpoint = route.get("endpoint", "")
        got = (
            r.get("status") == "active"
            and r.get("actor_id") == doc["expected_actor_id"]
            and r.get("public_key") == doc["expected_public_key"]
            and bool(endpoint)
            and verify_b64(
                r.get("public_key", ""),
                c.get("proof", ""),
                sendpath_canonical(r.get("actor_id", ""), r.get("name", ""), endpoint),
            )
        )
        passed = got == c["expect_bound"]
        ok += int(passed)
        print_case(passed, c["name"], got, c["expect_bound"])
    return ok, total


def verify_mux() -> tuple[int, int]:
    doc = load("mux_lane_v3.json")
    channels = {c["channel_id"]: c for c in doc["channels"]}
    ok = total = 0
    print("### v3 - mux lane")
    for c in doc["cases"]:
        total += 1
        frame = c["frame"]
        ch = channels.get(frame.get("channel_id"))
        got = bool(ch and frame.get("surface") == ch["surface"] and frame.get("intent") in ch["allowed_intents"])
        passed = got == c["expect_deliver"]
        ok += int(passed)
        print_case(passed, c["name"], got, c["expect_deliver"])
    return ok, total


def verify_overlay() -> tuple[int, int]:
    doc = load("overlay_route_v4.json")
    ok = total = 0
    print("### v4 - overlay route")
    for c in doc["cases"]:
        total += 1
        before, after = c["before"], c["after"]
        got = before["actor_id"] == after["actor_id"] and before["public_key"] == after["public_key"]
        passed = got == c["expect_same_actor"]
        ok += int(passed)
        print_case(passed, c["name"], got, c["expect_same_actor"])
    return ok, total


def verify_ipoll() -> tuple[int, int]:
    doc = load("ipoll_v5.json")
    seen = set(doc["seen"])
    delivered = set(doc["delivered"])
    allowed = {"PUSH", "PULL", "SYNC", "TASK", "ACK"}
    ok = total = 0
    print("### v5 - I-Poll envelope")
    for c in doc["cases"]:
        total += 1
        m = c["message"]
        base = (
            m.get("kind") in allowed
            and str(m.get("from_actor", "")).startswith("jis:")
            and str(m.get("to_aint", "")).endswith(".aint")
            and m.get("message_id") not in seen
            and verify_b64(m.get("from_pubkey", ""), m.get("signature", ""), ipoll_canonical(m))
        )
        if m.get("kind") == "ACK":
            got = base and m.get("ack_for") in delivered
        else:
            got = base
        passed = got == c["expect_deliver"]
        ok += int(passed)
        print_case(passed, c["name"], got, c["expect_deliver"])
    return ok, total


def verify_cmail() -> tuple[int, int]:
    doc = load("cmail_light_v6.json")
    ok = total = 0
    print("### v6 - Cmail Light")
    for c in doc["cases"]:
        total += 1
        e = c["envelope"]
        computed = sha256_text(e["subject"] + "\n" + e["body"])
        got = (
            e.get("kind") == "cmail.message.v1"
            and computed == e.get("content_hash")
            and str(e.get("from", "")).endswith(".aint")
            and str(e.get("to", "")).endswith(".aint")
        )
        passed = got == c["expect_valid"]
        ok += int(passed)
        print_case(passed, c["name"], got, c["expect_valid"])
    return ok, total


def verify_sealed() -> tuple[int, int]:
    doc = load("sealed_cmail_v7.json")
    ok = total = 0
    print("### v7 - sealed Cmail")
    for c in doc["cases"]:
        total += 1
        carrier = c["carrier"]
        hash_ok = sha256_text(carrier["sealed_payload"]) == carrier["content_hash"]
        accepted = (
            carrier.get("carrier_kind") == "tza.sealed.v1"
            and hash_ok
            and carrier.get("continuity_state") in {"arrived", "verified"}
            and verify_b64(
                carrier.get("sealer_pubkey", ""), carrier.get("signature", ""), sealed_canonical(carrier)
            )
        )
        got = "accept" if accepted else "quarantine"
        passed = got == c["expect_decision"]
        ok += int(passed)
        print_case(passed, c["name"], got, c["expect_decision"])
    return ok, total


def verify_gateway() -> tuple[int, int]:
    doc = load("gateway_egress_v8.json")
    allowed_hosts = set(doc["allowed_hosts"])
    ok = total = 0
    print("### v8 - gateway egress")
    for c in doc["cases"]:
        total += 1
        r = c["request"]
        proxy = (
            r.get("target_host") in allowed_hosts
            and str(r.get("actor_id", "")).startswith("jis:")
            and bool(r.get("intent"))
            and r.get("snaft_verdict") == "allow"
        )
        event = True
        passed = proxy == c["expect_proxy"] and event == c["expect_event"]
        ok += int(passed)
        print_case(passed, c["name"], {"proxy": proxy, "event": event}, {"proxy": c["expect_proxy"], "event": c["expect_event"]})
    return ok, total


def verify_null_route() -> tuple[int, int]:
    doc = load("null_route_v9.json")
    ok = total = 0
    print("### v9 - null route")
    for c in doc["cases"]:
        total += 1
        verdict = c["verdict"]
        if verdict == "allow":
            got = "deliver"
        elif verdict == "quarantine":
            got = "quarantine"
        else:
            got = "null-route"
        passed = got == c["expect_route"]
        ok += int(passed)
        print_case(passed, c["name"], got, c["expect_route"])
    return ok, total


def print_case(passed: bool, name: str, got, expect) -> None:
    mark = "PASS" if passed else "FAIL"
    print(f"  [{mark}] {name:28s} got={got!r} expect={expect!r}")


def main() -> int:
    suites = [
        verify_ping,
        verify_sendpath,
        verify_mux,
        verify_overlay,
        verify_ipoll,
        verify_cmail,
        verify_sealed,
        verify_gateway,
        verify_null_route,
    ]
    passed = total = 0
    for suite in suites:
        ok, n = suite()
        passed += ok
        total += n
        print()
    if passed == total:
        print("YES IT PLAYS — comms vectors are internally consistent. That is not interop.")
        print("Interop challenge: implement your own verifier against vectors/*.json.")
        return 0
    print(f"FAIL — {passed}/{total} cases passed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
