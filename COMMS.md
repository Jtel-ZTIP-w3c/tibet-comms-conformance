# COMMS.md - TIBET Communication Primitive Atlas

The map of the load-bearing communication surface: the small set of things a second
implementation must agree on to resolve, reach, route, deliver, reject, and prove a message
without a vendor in the loop.

## Invariant

```text
identity = JIS key
namespace = AINS / .aint
surface = SSM lane
transport = replaceable
verdict = explicit
```

Network addresses are route hints, not identities. `.aint` names are namespace entries, not
identities. SSM labels a semantic lane, not an authority. Every trust decision binds to a
resolved JIS actor key plus the relevant lane and policy context.

## Atlas

```text
                 L6 observability       cap-bus · cascade · tail · trail
                       │                what happened across lanes?
                 L5 edge / egress       gateway · SNAFT · cost-watch
                       │                may this leave the membrane?
                 L4 message transport   I-Poll · Cmail · sealed Cmail
                       │                did the object arrive as intended?
                 L3 topology            overlay
                       │                actor survives NAT/IP movement
                 L2 routing             mux · NullRouteMux
                       │                one socket, many lanes, wrong lane denied
                 L1 reachability        tibet-ping
                       │                is the actor/surface/lane alive?
                 L0 identity/surface    JIS · AINS · SSM · TIBET
                       │                who, where, which lane, what proof?
                 floor                  trust-kernel / OSAPI
```

## L0 - Identity / Namespace / Surface

| Primitive | Role |
|---|---|
| JIS | canonical actor identity, Ed25519/FIR-A challenge-response |
| AINS / `.aint` | namespace and discovery: name -> key / endpoint / capability |
| SSM | semantic surface manifest: lane label before payload trust |
| TIBET | provenance: every route, decision, and delivery can be sealed |

## L1 - Reachability

`tibet-ping` asks layered questions:

- is anything reachable?
- does a JIS-shaped target parse?
- does AINS resolve this name?
- is mux listening?
- does the full stack look alive?

The conformance primitive is not ICMP. It is a signed, nonce-bearing probe whose result is
bound to actor, surface, timestamp, and route class.

## L2 - Routing

`tibet-mux` turns one connection into many SSM/intention lanes. `NullRouteMux` is the routing
enforcement sibling: wrong lane, denied posture, or spoofed route becomes quarantine/null.

Interop here means lane isolation: two payloads on one connection cannot cross lanes, and a
verdict can force a route outcome deterministically.

## L3 - Topology

`tibet-overlay` makes identity independent of IP. A route may change from one endpoint to
another, but the actor remains the same only if the JIS key remains the same.

Interop here means CGNAT/roaming-safe identity: endpoint change does not change identity;
same IP does not prove same actor.

## L4 - Message Transport

`I-Poll` is the asynchronous agent transport: `PUSH`, `PULL`, `SYNC`, `TASK`, `ACK`.

`Cmail` is the human-readable envelope over that transport. Light Mode is hash-checked JSON;
Sealed Mode carries a `.tza`/TBZ object into continuityd.

## L5 - Edge / Egress

`tibet-gateway` is the membrane for external calls. It checks target host, actor, intent,
policy, and emits an event. It must not confuse external reachability with permission.

## L6 - Observability

`tibet-cap-bus.gateway-event.v1`, `tibet-cascade`, `tibet-tail`, and `tibet-trail` turn
communication into traceable events. This is not a separate transport; it is the audit lane
that proves the route decision happened.

## Products Out Of Scope

The following consume the comms surface but are not the primitive contract:

- Cmail UI
- Phantom / Home Agent
- KIT / ID-Drop apps
- model bridges
- long-tail runtime packages

Their package placement belongs in `stack-position-map.yml`, not this atlas.
