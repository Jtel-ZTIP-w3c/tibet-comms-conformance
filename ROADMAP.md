# Roadmap

One communication primitive at a time. Each level is deterministic and offline first.

| Level | Primitive | Status |
|---:|---|---|
| v1 | ping frame | structural |
| v2 | AINS sendpath | **signed (Ed25519)** |
| v3 | mux lane isolation | structural |
| v4 | overlay route identity | structural |
| v5 | I-Poll envelope | **signed (Ed25519)** |
| v6 | Cmail Light envelope | structural |
| v7 | sealed Cmail carrier | **signed (Ed25519)** |
| v8 | gateway egress decision | structural |
| v9 | null-route enforcement | structural |
| v10 | mux status frame (two-way heartbeat_dead) | structural |

## Family

Public at `Jtel-ZTIP-w3c/tibet-comms-conformance`, one of four kits (identity / comms / evidence /
security). The primitive atlas is the hub `INTEROP.md`.

## From structural to signed

The envelope levels `v5` (I-Poll) and `v7` (sealed Cmail) now carry **real Ed25519 signatures**
(`ref/_crypto.py` + `ref/generate_signed.py`, deterministic fixed-seed; each has a `bad-signature`
negative case the verifier rejects). Next, to take the remaining levels from structural to
cryptographic:

- Ed25519 over the canonical for the key-bearing levels (`v2` sendpath, `v4` overlay route);
- `gateway-event.v1` payload samples for `v8`;
- real TBZ/.tza byte fixtures (shared with `tibet-evidence-conformance`);
- more negative vectors: malformed base64, wrong actor, stale nonce, lane spoofing.
