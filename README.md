# lau-a2a-protocol

> Agent-to-Agent communication layer — how PLATO agents discover, authenticate, route, and talk to each other.

## What This Does

This crate defines the wire protocol for inter-agent communication in the PLATO ecosystem. It provides:

- **Agent discovery** via `AgentCard` — business cards agents advertise to the network
- **Message routing** via `A2ARouter` — direct delivery, topic broadcast, and fuzzy search
- **Session management** via `A2ASession` — multi-turn conversations with lifecycle tracking
- **Message authentication** via HMAC-SHA256 — sign and verify messages to prevent tampering
- **Flexible payloads** — text, JSON, binary (hex-encoded), and multipart

If you have two agents that need to find each other, exchange messages, and verify authenticity — this is the layer.

## The Key Idea

Think of it as a **post office for agents**. Every agent registers a "business card" (`AgentCard`) that advertises what it can do. The `A2ARouter` acts as the sorting facility — it can deliver messages directly (by agent ID), broadcast to topic subscribers, or fuzzy-search the directory. Messages can be signed with HMAC-SHA256 so the recipient knows they haven't been tampered with. Sessions track multi-turn conversations between agents.

```
┌──────────┐    AgentCard     ┌──────────┐
│ Agent A  │ ────Register────→ │  Router   │
│ (scout)  │                   │ (routes)  │
└────┬─────┘                   └─────┬─────┘
     │                               │
     │  A2AMessage (signed)          │ route()
     │ ─────────────────────────────→│
     │                               │ ──→ ┌──────────┐
     │                               │     │ Agent B  │
     │                               │     │ (builder)│
     │                               │     └──────────┘
```

## Install

```bash
cargo add lau-a2a-protocol
```

**Dependencies:** `serde`, `serde_json`, `hmac`, `sha2`, `hex`

## Quick Start

```rust
use lau_a2a_protocol::*;

// 1. Create agent business cards
let card_a = AgentCard {
    id: "agent-alpha".into(),
    name: "Alpha".into(),
    version: "1.0.0".into(),
    description: "A translation agent".into(),
    capabilities: vec!["translation".into(), "summarization".into()],
    protocols: vec!["https".into()],
    endpoints: vec![AgentEndpoint {
        url: "https://alpha.example.com".into(),
        protocol: "https".into(),
        description: "main".into(),
    }],
    authentication: Some(AuthScheme::ApiKey { header: "X-API-Key".into() }),
    metadata: Default::default(),
};

// 2. Register with the router
let mut router = A2ARouter::new();
router.register_agent(card_a);

// 3. Discover agents by capability
let translators = router.find_by_capability("translation");

// 4. Create and sign a message
let mut msg = A2AMessage {
    id: "msg-1".into(),
    from: "agent-alpha".into(),
    to: "agent-beta".into(),
    message_type: A2AMessageType::Query { intent: "translate".into() },
    payload: A2APayload::Text("Hello, world!".into()),
    metadata: Default::default(),
    timestamp: 1000,
    ttl: Some(60),
    signature: None,
};
msg.sign(b"secret-key");
assert!(msg.verify(b"secret-key"));

// 5. Route it
let targets = router.route(&msg);
```

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `AgentCard` | Agent identity card — used for discovery and advertisement. Fields: `id`, `name`, `version`, `description`, `capabilities`, `protocols`, `endpoints`, `authentication`, `metadata`. |
| `AgentEndpoint` | A network endpoint. Fields: `url`, `protocol`, `description`. |
| `AuthScheme` | Authentication scheme. Variants: `None`, `ApiKey { header }`, `OAuth2 { scopes }`, `MutualTLS`, `Custom(String)`. |
| `A2AMessage` | A single protocol message. Fields: `id`, `from`, `to`, `message_type`, `payload`, `metadata`, `timestamp`, `ttl`, `signature`. |
| `A2AMessageType` | Message type discriminator. See below. |
| `A2APayload` | Message content. Variants: `Text(String)`, `Json(String)`, `Binary(Vec<u8>)` (hex-encoded in JSON), `MultiPart(Vec<A2APayload>)`. |
| `A2ASession` | A conversation session. Fields: `session_id`, `participants`, `messages`, `state`. |
| `SessionState` | Session lifecycle: `Active`, `Idle`, `Closed`, `Error(String)`. |
| `A2ARouter` | Routes messages between agents. Manages registration, subscriptions, and discovery. |
| `A2AError` | Error type: `AgentNotFound`, `NoRoute`, `InvalidPayload`, `AuthFailed`, `Timeout`, `Serialization`. |

### Message Types (`A2AMessageType`)

| Variant | Purpose |
|---------|---------|
| `Discover` | Look for agents on the network |
| `Advertise(AgentCard)` | Broadcast an agent's capabilities |
| `Query { intent }` | Ask another agent a question |
| `Response { result }` | Reply to a query |
| `Delegate { task, target }` | Assign work to another agent |
| `Notify { event }` | Push notification |
| `Subscribe { topics }` | Subscribe to topic-based routing |
| `Unsubscribe` | Stop receiving topic messages |
| `Heartbeat` | Keep-alive ping |
| `Error { code, message }` | Error response |

### Methods

#### `AgentCard`
- `to_json(&self) -> String` — Serialize to JSON.
- `from_json(s: &str) -> Result<Self, A2AError>` — Deserialize from JSON.

#### `A2APayload`
- `as_text(&self) -> Option<&str>` — Extract text if this is a `Text` payload.
- `as_json<T: DeserializeOwned>(&self) -> Option<T>` — Parse JSON payload into a typed value.

#### `A2AMessage`
- `sign(&mut self, key: &[u8])` — Sign with HMAC-SHA256.
- `verify(&self, key: &[u8]) -> bool` — Verify HMAC signature (constant-time comparison).

#### `A2ASession`
- `new(session_id, participants) -> Self` — Create an active session.
- `add_message(&mut self, message)` — Append a message; reactivates `Idle` → `Active`.
- `history(&self) -> &[A2AMessage]` — Full message history.
- `is_active(&self) -> bool` — True if `Active` or `Idle`.
- `close(&mut self)` — Transition to `Closed`.

#### `A2ARouter`
- `register_agent(&mut self, card)` — Register an agent. Overwrites if ID exists.
- `unregister_agent(&mut self, id)` — Remove agent and all its subscriptions.
- `subscribe(&mut self, agent_id, topics)` — Subscribe to topic-based routing.
- `unsubscribe(&mut self, agent_id, topics)` — Remove subscriptions.
- `route(&self, message) -> Vec<String>` — Resolve targets: direct ID → topic subscribers → empty.
- `find_by_capability(&self, capability) -> Vec<&AgentCard>` — Find agents declaring a capability.
- `find_by_protocol(&self, protocol) -> Vec<&AgentCard>` — Find agents supporting a protocol.
- `discover(&self, query) -> Vec<&AgentCard>` — Fuzzy search name, description, and capabilities.

## How It Works

### Discovery
Agents register `AgentCard`s with the router. The `discover` method performs case-insensitive substring matching across name, description, and capabilities. No external service directory needed — everything is in-memory.

### Routing
The `route` method resolves destinations in priority order:
1. **Direct delivery**: if `to` matches a registered agent ID
2. **Topic broadcast**: if `to` matches a topic with subscribers
3. **No match**: returns an empty vec

### Message Signing
Messages use HMAC-SHA256 over a canonical string: `id|from|to|message_type_json|payload_json|timestamp`. The signature is hex-encoded and stored in the `signature` field. Verification uses constant-time byte comparison to prevent timing attacks:

```rust
// Constant-time comparison (XOR accumulator)
let mut acc: u8 = 0;
for (a, b) in sig_bytes.iter().zip(expected_bytes.iter()) {
    acc |= a ^ b;
}
acc == 0  // true only if all bytes match
```

### Sessions
Track multi-turn conversations with lifecycle states:
- `Active` → normal operation
- `Idle` → no recent activity, but still open
- `Closed` → terminated (stays closed even if messages arrive)
- `Error(String)` — broken session

Adding a message to an `Idle` session automatically reactivates it to `Active`.

### Payload Handling
Binary payloads are hex-encoded for JSON transport. `MultiPart` payloads nest arbitrarily. The `as_text()` and `as_json::<T>()` convenience methods extract typed content without matching on variants.

## The Math

### Routing as Graph Traversal
The routing model is a bipartite graph between agents and topics:
- **Direct edges**: `agent → agent` (via registered IDs)
- **Topic edges**: `agent ↔ topic` (via subscriptions)
- **Route resolution**: given `(from, to)`, find all reachable agent nodes

### HMAC-SHA256 Security
HMAC-SHA256 provides information-theoretic security for message authentication:
- Without the key, the probability of forging a valid signature is ≤ 2^(-256)
- The 256-bit tag length makes brute-force infeasible
- Constant-time verification prevents timing side-channels

## Testing

**54 tests** covering:
- Agent card JSON round-trips (including metadata and auth)
- All `AuthScheme` variant serialization
- Payload text/JSON/binary/multipart round-trips and edge cases
- Message signing, verification, wrong-key rejection, tampering detection
- Session lifecycle (new, add, idle→active reactivation, close stays closed)
- Router: register, unregister, direct routing, topic routing, capability/protocol search, fuzzy discovery, case-insensitive matching
- Multi-agent topic broadcast
- Edge cases: empty router operations, re-registration overwrites, multi-agent sessions

```bash
cargo test    # Run all 54 tests
```

## License

MIT
