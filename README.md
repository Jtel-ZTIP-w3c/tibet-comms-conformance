# TIBET Comms Conformance Kit

**Prove that TIBET-native communication interoperates without trusting the vendor.**

This is a sandbox prototype for a future public `tibet-comms-conformance` repo. It mirrors
the style of `ztip-conformance`: runnable vectors, explicit negative cases, and a reference
runner that proves only internal consistency. The vectors are the contract.

## What this repo is

This is an **interoperability kit, not an SDK**.

The conformance contract is the JSON vector set in [`vectors/`](vectors/). The reference
runner in [`ref/`](ref/) is only one implementation. A real interop claim requires a second
implementation, in any language, that consumes the same vectors and returns the same results.

> **Do not trust this repo's scripts.** Run them to see the reference pass, then implement
> your own verifier against the vectors. Same zero-trust rule as the protocol itself.

## Quickstart

No third-party dependencies.

```sh
./run.sh
```

Expected ending:

```text
YES IT PLAYS — comms vectors are internally consistent. That is not interop.
Interop challenge: implement your own verifier against vectors/*.json.
```

## What this proves

The kit covers the communication branch of the stack:

| Level | Primitive | Vector |
|---:|---|---|
| v1 | ping frame | `vectors/ping_v1.json` |
| v2 | AINS sendpath | `vectors/sendpath_v2.json` |
| v3 | mux lane isolation | `vectors/mux_lane_v3.json` |
| v4 | overlay route identity | `vectors/overlay_route_v4.json` |
| v5 | I-Poll envelope | `vectors/ipoll_v5.json` |
| v6 | Cmail Light envelope | `vectors/cmail_light_v6.json` |
| v7 | sealed Cmail carrier | `vectors/sealed_cmail_v7.json` |
| v8 | gateway egress decision | `vectors/gateway_egress_v8.json` |
| v9 | null-route enforcement | `vectors/null_route_v9.json` |

## Shape

```text
tibet-comms-conformance/
  COMMS.md          primitive atlas
  SPEC.md           byte/logic rules for v1-v9
  IMPLEMENTER.md    how to build your own verifier
  CONFORMANCE.md    what counts as conformant
  ROADMAP.md        level map
  vectors/          public contract
  ref/              reference runner only
```

## Not product docs

This is not a catalogue of all packages. It only maps the load-bearing communication
surface: reachability, route selection, lane isolation, delivery envelopes, egress policy,
and enforcement verdicts.

Products such as Cmail UI, Phantom, Home Agent, KIT, ID-Drop, and the long-tail bridges
consume this surface. They are not the conformance contract.

---

## Part of the conformance family

Four runnable kits, one per branch of the stack. Run any, implement your own verifier against its
vectors, interoperate with no vendor in the loop. Together they let a second implementation
reconstruct the whole spine from the vectors alone.

- [ztip-conformance](https://github.com/Jtel-ZTIP-w3c/ztip-conformance) — identity / attestation / ceremony
- [tibet-comms-conformance](https://github.com/Jtel-ZTIP-w3c/tibet-comms-conformance) — communication / routing
- [tibet-evidence-conformance](https://github.com/Jtel-ZTIP-w3c/tibet-evidence-conformance) — storage / evidence
- [tibet-security-conformance](https://github.com/Jtel-ZTIP-w3c/tibet-security-conformance) — policy / enforcement

Primitive atlas: https://github.com/Jtel-ZTIP-w3c/Jtel-ZTIP-w3c.github.io (INTEROP.md).
