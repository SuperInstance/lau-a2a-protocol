# lau-a2a-protocol

Agent-to-Agent (A2A) protocol layer for PLATO — defines how agents discover, authenticate, route, and communicate with each other.

## Core Types

| Type | Purpose |
|------|---------|
| `AgentCard` | Agent identity and discovery metadata |
| `AgentEndpoint` | Network endpoint (https, grpc, file, stdio) |
| `AuthScheme` | Authentication scheme (None, ApiKey, OAuth2, MutualTLS, Custom) |
| `A2AMessage` | Protocol message with HMAC signing/verification |
| `A2AMessageType` | Message type enum (Discover, Query, Delegate, Notify, etc.) |
| `A2APayload` | Flexible payload (Text, Json, Binary, MultiPart) |
| `A2ARouter` | Routes messages, manages agent registry and topic subscriptions |
| `A2ASession` | Conversation session between agents |

## Usage

```rust
use lau_a2a_protocol::*;

// Create and register agents
let mut router = A2ARouter::new();
router.register_agent(AgentCard {
    id: "translator".into(),
    name: "Translator Bot".into(),
    version: "1.0.0".into(),
    description: "Translates text between languages".into(),
    capabilities: vec!["translation".into()],
    protocols: vec!["https".into()],
    endpoints: vec![AgentEndpoint {
        url: "https://translator.example.com".into(),
        protocol: "https".into(),
        description: "REST API".into(),
    }],
    authentication: Some(AuthScheme::ApiKey { header: "X-API-Key".into() }),
    metadata: Default::default(),
});

// Discover agents
let agents = router.discover("translate");

// Route messages
let msg = A2AMessage { /* ... */ };
let targets = router.route(&msg);

// Sign and verify
msg.sign(b"secret-key");
assert!(msg.verify(b"secret-key"));
```

## License

MIT
