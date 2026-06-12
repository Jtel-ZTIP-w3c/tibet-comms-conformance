# Implementer Guide

Goal: build an independent verifier that agrees with the public vectors.

## Rules

1. Read JSON from `vectors/`.
2. Implement the checks yourself, per `SPEC.md`.
3. Match each case's expected output.
4. Positive cases must pass; negative cases must fail.
5. Any language is valid.
6. You may read `ref/verify_all.py`, but do not import it and call that interop.

## Per-Level Work

| Level | What to implement |
|---:|---|
| v1 | ping frame TTL, JIS actor shape, SSM surface shape |
| v2 | `.aint` sendpath resolution and key binding |
| v3 | mux channel/lane isolation |
| v4 | overlay route identity across endpoint changes |
| v5 | I-Poll message delivery, duplicate rejection, ACK reference |
| v6 | Cmail Light content hash and kind filtering |
| v7 | sealed carrier hash + continuity-state decision |
| v8 | gateway host allowlist + SNAFT verdict + event emission |
| v9 | verdict-driven null-route/quarantine/deliver routing |

## Why This Matters

Communication interop is not "can my HTTP client call your server?"

It is:

```text
Can a second implementation resolve an actor, select a semantic lane, route a message,
reject the wrong lane, and produce the same delivery/verdict event without our code?
```

That is the bar.
