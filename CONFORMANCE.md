# Conformance

An implementation is conformant at level `vN` when it consumes the corresponding vector
file and produces the expected result for every case.

| Level | Vector file | Proves |
|---:|---|---|
| v1 | `vectors/ping_v1.json` | signed/nonce-like reachability frame semantics |
| v2 | `vectors/sendpath_v2.json` | AINS sendpath binds by JIS key, not name |
| v3 | `vectors/mux_lane_v3.json` | one connection, isolated lanes |
| v4 | `vectors/overlay_route_v4.json` | identity survives endpoint change; IP is not identity |
| v5 | `vectors/ipoll_v5.json` | async PUSH/PULL/ACK envelope semantics |
| v6 | `vectors/cmail_light_v6.json` | Cmail Light content hash + inbox filtering |
| v7 | `vectors/sealed_cmail_v7.json` | sealed carrier accept/quarantine decision |
| v8 | `vectors/gateway_egress_v8.json` | allowed egress vs blocked egress with event emission |
| v9 | `vectors/null_route_v9.json` | verdict-driven delivery/quarantine/null-route |
| v10 | `vectors/mux_status_v10.json` | two-way heartbeat_dead status; relationship-scoped silence (anti-enumeration) |

## What Counts As Proof

- Passing `./run.sh` proves this reference runner is internally consistent.
- Passing the vectors from an independent implementation proves interoperability.

Claims should name:

- covered levels;
- vector files;
- implementation language/runtime;
- whether code imports any reference logic from this kit.

Importing `ref/verify_all.py` is not an interop proof.
