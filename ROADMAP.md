# Roadmap

One communication primitive at a time. Each level is deterministic and offline first.

| Level | Primitive | Status |
|---:|---|---|
| v1 | ping frame | sandbox live |
| v2 | AINS sendpath | sandbox live |
| v3 | mux lane isolation | sandbox live |
| v4 | overlay route identity | sandbox live |
| v5 | I-Poll envelope | sandbox live |
| v6 | Cmail Light envelope | sandbox live |
| v7 | sealed Cmail carrier | sandbox live |
| v8 | gateway egress decision | sandbox live |
| v9 | null-route enforcement | sandbox live |

## Future Public Repo Shape

If promoted out of Codex sandbox:

```text
Jtel-ZTIP-w3c/ztip-conformance       identity / attestation branch
Humotica/tibet-comms-conformance     communication / routing branch
Hub COMMS.md                         atlas that links both
```

## Next Real Vectors

The sandbox vectors are logical. Public v1 should add cryptographic material:

- Ed25519 signatures for ping frames;
- canonical SSM field ordering;
- gateway-event.v1 payload samples;
- TBZ/.tza hash samples;
- negative vectors with malformed base64, wrong actor, stale nonce, and lane spoofing.
