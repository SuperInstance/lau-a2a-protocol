# lau-a2a-protocol

> Agent-to-Agent communication layer — how PLATO agents discover, authenticate, route, and talk to each other.

## What This Does

This crate defines the wire protocol for inter-agent communication in the PLATO ecosystem. It provides agent discovery (via `AgentCard`), message routing (via `A2ARouter`), session management, and HMAC-SHA256 message signing. If you have two agents that need to find each other, exchange messages, and verify authenticity — this is the layer.

## The Key Idea

Think of it as a post office for agents. Every agent registers a "business card" (`AgentCard`) that advertises what it can do. The `A2ARouter` acts as the sorting facility — it can deliver messages directly, broadcast to topic subscribers, or fuzzy-search the directory. Messages can be signed with HMAC-SHA256 so the recipient knows they haven't been tampered with. Sessions track multi-turn conversations between agents.

## Install

```bash
cargo add lau-a2a-protocol
```

## Quick Start

```rust
use lau_a2a_protocol::*;

// Create agent business cards
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

// Register with the router
let mut router = A2ARouter::new();
router.register_agent(card_a);

// Discover agents by capability
let translators = router.find_by_capability("translation");

// Create and sign a message
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

// Route it
let targets = router.route(&msg);
```

## API Reference

### Types

| Type | Description |
|------|-------------|
| `AgentCard` | Agent identity card — used for discovery and advertisement. Fields: `id`, `name`, `version`, `description`, `capabilities`, `protocols`, `endpoints`, `authentication`, `metadata`. |
| `AgentEndpoint` | A network endpoint. Fields: `url`, `protocol`, `description`. |
| `AuthScheme` | Authentication scheme. Variants: `None`, `ApiKey { header }`, `OAuth2 { scopes }`, `MutualTLS`, `Custom(String)`. |
| `A2AMessage` | A single protocol message. Fields: `id`, `from`, `to`, `message_type`, `payload`, `metadata`, `timestamp`, `ttl`, `signature`. |
| `A2AMessageType` | Message type discriminator. Variants: `Discover`, `Advertise(AgentCard)`, `Query { intent }`, `Response { result }`, `Delegate { task, target }`, `Notify { event }`, `Subscribe { topics }`, `Unsubscribe`, `Heartbeat`, `Error { code, message }`. |
| `A2APayload` | Message content. Variants: `Text(String)`, `Json(String)`, `Binary(Vec<u8>)` (hex-encoded in JSON), `MultiPart(Vec<A2APayload>)`. |
| `A2ASession` | A conversation session. Fields: `session_id`, `participants`, `messages`, `state`. |
| `SessionState` | Session lifecycle state. Variants: `Active`, `Idle`, `Closed`, `Error(String)`. |
| `A2ARouter` | Routes messages between agents. Manages registration, subscriptions, and discovery. |
| `A2AError` | Error type. Variants: `AgentNotFound`, `NoRoute`, `InvalidPayload`, `AuthFailed`, `Timeout`, `Serialization`. |

### Key Methods

#### `AgentCard`
- `to_json(&self) -> String` — Serialize to JSON.
- `from_json(s: &str) -> Result<Self, A2AError>` — Deserialize from JSON.

#### `A2APayload`
- `as_text(&self) -> Option<&str>` — Extract text if this is a `Text` payload.
- `as_json<T: DeserializeOwned>(&self) -> Option<T>` — Parse JSON payload into a typed value.

#### `A2AMessage`
- `sign(&mut self, key: &[u8])` — Sign with HMAC-SHA256.
- `verify(&self, key: &[u8]) -> bool` — Verify HMAC signature. Constant-time comparison.

#### `A2ASession`
- `new(session_id, participants) -> Self` — Create an active session.
- `add_message(&mut self, message)` — Append a message, reactivating idle sessions.
- `history(&self) -> &[A2AMessage]` — Full message history.
- `is_active(&self) -> bool` — True if `Active` or `Idle`.
- `close(&mut self)` — Transition to `Closed`.

#### `A2ARouter`
- `register_agent(&mut self, card)` — Register an agent. Overwrites if ID exists.
- `unregister_agent(&mut self, id)` — Remove agent and all its subscriptions.
- `subscribe(&mut self, agent_id, topics)` — Subscribe to topic-based routing.
- `unsubscribe(&mut self, agent_id, topics)` — Remove subscriptions.
- `route(&self, message) -> Vec<String>` — Resolve targets: direct ID, topic subscribers, or empty.
- `find_by_capability(&self, capability) -> Vec<&AgentCard>` — Find agents declaring a capability.
- `find_by_protocol(&self, protocol) -> Vec<&AgentCard>` — Find agents supporting a protocol.
- `discover(&self, query) -> Vec<&AgentCard>` — Fuzzy search name, description, and capabilities.

## How It Works

**Discovery** — Agents register `AgentCard`s with the router. The `discover` method does case-insensitive substring matching across name, description, and capabilities.

**Routing** — The `route` method first checks if `to` is a registered agent ID (direct delivery), then checks if it's a topic with subscribers (broadcast), and finally returns empty if neither matches.

**Signing** — Messages use HMAC-SHA256 over a canonical payload string (`id|from|to|message_type|payload|timestamp`). The signature is hex-encoded. Verification uses constant-time comparison to prevent timing attacks.

**Sessions** — Track multi-turn conversations. Adding a message to an `Idle` session reactivates it to `Active`. Closed sessions stay closed.

## The Math

The routing model is a bipartite graph between agents and topics:
- Direct edges: `agent → agent` (via registered IDs)
- Topic edges: `agent ↔ topic` (via subscriptions)
- Route resolution is graph traversal: given `(from, to)`, find all reachable agent nodes

HMAC-SHA256 provides information-theoretic security: without the key, the probability of forging a valid signature is ≤ 2^(-256).

## Testing

**50 tests** covering:
- Agent card JSON round-trips
- All `AuthScheme` variant serialization
- Payload text/JSON/binary/multipart round-trips
- Message signing, verification, tampering detection
- Session lifecycle (new, add, idle→active, close)
- Router: register, unregister, direct routing, topic routing, capability/protocol search, fuzzy discovery
- Edge cases: empty router, re-registration, multi-agent broadcast

## License

MIT
