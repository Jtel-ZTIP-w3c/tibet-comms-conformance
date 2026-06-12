# TIBET Comms Conformance - SPEC

This spec defines the deterministic offline vectors in this kit. It is intentionally small:
every level is a rule a second implementation can reproduce without a live server.

## Maturity (read this first)

**Mixed maturity, labelled per level.** The envelope levels **`v5` (I-Poll) and `v7` (sealed Cmail)
carry real Ed25519 signatures** — verifiable, deterministic, derived from a fixed seed
(`ref/_crypto.py` + `ref/generate_signed.py`), the same idiom as `ztip-conformance`. Each has a
`bad-signature` case that the verifier rejects. The remaining levels are **structural**: they prove
decision-logic conformance (same inputs → same route / status / verdict) on *placeholder* keys, with
real signing / real bytes as the next step (see ROADMAP). So a conformant verifier checks real
cryptography at v5/v7 and shape / freshness / ordering / routing elsewhere.

## Determinism — the clock is in the vector

Freshness rules below use `now`. `now` is **not** the system clock: it is the vector's top-level
`verify_at` field (a Unix timestamp). A conformant verifier MUST evaluate freshness against
`verify_at` and MUST NOT read the wall clock — otherwise two correct implementations diverge on the
very first run. The reference runner does exactly this; the rule is stated here, normatively, so a
spec-only implementer (who, per this kit's own premise, does not trust the scripts) matches it from
the contract alone.

## Shared Terms

- `actor_id`: canonical JIS actor identifier.
- `actor_key`: base64 Ed25519 public key placeholder in vectors. These sandbox vectors do
  not require real signatures yet; they model the checks that future crypto vectors should
  sign.
- `aint`: AINS namespace label.
- `surface`: SSM lane label.
- `route`: selected communication route.
- `verdict`: allow / deny / quarantine / null-route decision.
- `verify_at`: top-level Unix timestamp in each vector file — the *only* clock for freshness
  checks (see Determinism). The verifier never reads the system clock.

## v1 - Ping Frame

A ping frame checks reachability for an actor and surface.

Accept rule:

```text
ok := actor_id starts with "jis:"
      AND nonce is non-empty
      AND now < issued_at + ttl_seconds
      AND surface has four dot-separated parts
```

Expected statuses:

- `ALIVE` when `ok` is true.
- `STALE` when the TTL is expired.
- `BAD_SURFACE` when the surface is not SSM-shaped.
- `BAD_ACTOR` when actor is not canonical JIS.

## v2 - AINS Sendpath

A sendpath resolves a `.aint` namespace label to an actor key and endpoint.

Binding rule:

```text
bound := record exists
         AND record.status == "active"
         AND record.actor_id == expected_actor_id
         AND record.public_key == expected_public_key
         AND route.endpoint exists
```

`.aint` is never identity. It is only a namespace entry that resolves to JIS identity.

## v3 - Mux Lane

One connection may carry many lanes. A frame is deliverable only on its selected lane.

```text
deliver := frame.channel_id exists
           AND frame.surface == channel.surface
           AND frame.intent is allowed for channel.backend
```

Wrong-lane frames must not be delivered to a different channel.

## v4 - Overlay Route

Identity survives endpoint movement; IP does not prove identity.

```text
same_actor := before.actor_id == after.actor_id
              AND before.public_key == after.public_key
```

Endpoint changes are acceptable when `same_actor` is true. Same endpoint with a different key
is not the same actor.

## v5 - I-Poll Envelope

I-Poll messages are asynchronous envelopes.

```text
deliver := kind in PUSH|PULL|SYNC|TASK|ACK
           AND from_actor starts with "jis:"
           AND to_aint ends with ".aint"
           AND message_id not seen before
           AND signature verifies under from_pubkey
```

ACK is valid only when it references a previously delivered message.

Signature: each envelope carries `from_pubkey` (base64 raw Ed25519) and `signature` (base64) over
the canonical `ipoll:v1:<kind>:<message_id>:<from_actor>:<to_aint>:<ack_for>` as UTF-8 bytes
(`ack_for` is the empty string for non-ACK kinds). The signature MUST verify or the message is not
delivered. The `bad-signature` case carries a well-formed signature over a *different* canonical and
must be rejected.

Dedup scope: `message_id not seen before` is evaluated **within a single vector file, in array
order** — earlier cases in the same file are what counts as "seen". There is no cross-file state
and no wall-clock involvement.

## v6 - Cmail Light Envelope

Cmail Light is a human-readable envelope with a deterministic body hash.

```text
content_hash := "sha256:" + sha256(subject + "\n" + body)
valid := kind == "cmail.message.v1"
         AND computed content_hash == envelope.content_hash
         AND to/from are namespace labels
```

Byte rule: `sha256` is computed over the **UTF-8 bytes** of `subject + "\n" + body` — with no
trailing newline and no Unicode normalization. A subject that looks identical but differs in
composed vs decomposed form (e.g. a `ö` as one codepoint or two) is a different input by design:
the bytes are the contract, not the glyphs.

Inbox filtering must ignore non-`cmail.message.v1` messages.

## v7 - Sealed Cmail Carrier

Sealed Cmail carries a `.tza` object into the continuity path.

```text
accept := carrier_kind == "tza.sealed.v1"
          AND content_hash matches sealed_payload
          AND continuity_state in ["arrived", "verified"]
          AND signature verifies under sealer_pubkey
```

`quarantine` is expected when hash verification fails.

Signature: the carrier carries `sealer_pubkey` (base64 raw Ed25519) and `signature` (base64) over
the canonical `tza.sealed:v1:<content_hash>:<continuity_state>` as UTF-8 bytes. A carrier whose
signature does not verify is quarantined even when the hash and state are valid — the
`bad-signature` case proves it.

## v8 - Gateway Egress

Gateway egress is a membrane decision.

```text
allow := host in allowed_hosts
         AND actor_id starts with "jis:"
         AND intent is non-empty
         AND snaft_verdict == "allow"
```

Denied hosts, malformed actors, or intent mismatch must not be proxied. They must still emit
an event.

## v9 - Null Route Enforcement

Null-route is deterministic routing enforcement.

```text
route_outcome :=
  "deliver"    if verdict == "allow"
  "quarantine" if verdict == "quarantine"
  "null-route" if verdict == "deny" or verdict == "null-route"
```

The payload must not decide its own route. The verdict decides.
