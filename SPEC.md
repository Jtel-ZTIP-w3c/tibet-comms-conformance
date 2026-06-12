# TIBET Comms Conformance - SPEC

This spec defines the deterministic offline vectors in this sandbox kit. It is intentionally
small: every level is a rule a second implementation can reproduce without a live server.

## Shared Terms

- `actor_id`: canonical JIS actor identifier.
- `actor_key`: base64 Ed25519 public key placeholder in vectors. These sandbox vectors do
  not require real signatures yet; they model the checks that future crypto vectors should
  sign.
- `aint`: AINS namespace label.
- `surface`: SSM lane label.
- `route`: selected communication route.
- `verdict`: allow / deny / quarantine / null-route decision.

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
```

ACK is valid only when it references a previously delivered message.

## v6 - Cmail Light Envelope

Cmail Light is a human-readable envelope with a deterministic body hash.

```text
content_hash := "sha256:" + sha256(subject + "\n" + body)
valid := kind == "cmail.message.v1"
         AND computed content_hash == envelope.content_hash
         AND to/from are namespace labels
```

Inbox filtering must ignore non-`cmail.message.v1` messages.

## v7 - Sealed Cmail Carrier

Sealed Cmail carries a `.tza` object into the continuity path.

```text
accept := carrier_kind == "tza.sealed.v1"
          AND content_hash matches sealed_payload
          AND continuity_state in ["arrived", "verified"]
```

`quarantine` is expected when hash verification fails.

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
