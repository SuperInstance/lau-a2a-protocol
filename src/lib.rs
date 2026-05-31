//! # lau-a2a-protocol
//!
//! Agent-to-Agent (A2A) protocol layer — how PLATO agents communicate
//! with each other and with non-PLATO agents.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during A2A operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum A2AError {
    AgentNotFound(String),
    NoRoute(String),
    InvalidPayload(String),
    AuthFailed(String),
    Timeout,
    Serialization(String),
}

impl fmt::Display for A2AError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            A2AError::AgentNotFound(id) => write!(f, "agent not found: {id}"),
            A2AError::NoRoute(msg) => write!(f, "no route: {msg}"),
            A2AError::InvalidPayload(msg) => write!(f, "invalid payload: {msg}"),
            A2AError::AuthFailed(msg) => write!(f, "auth failed: {msg}"),
            A2AError::Timeout => write!(f, "timeout"),
            A2AError::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for A2AError {}

// ---------------------------------------------------------------------------
// AuthScheme
// ---------------------------------------------------------------------------

/// Authentication scheme for an agent endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AuthScheme {
    None,
    ApiKey { header: String },
    OAuth2 { scopes: Vec<String> },
    MutualTLS,
    Custom(String),
}

// ---------------------------------------------------------------------------
// AgentEndpoint
// ---------------------------------------------------------------------------

/// A network endpoint where an agent can be reached.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEndpoint {
    pub url: String,
    pub protocol: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// AgentCard
// ---------------------------------------------------------------------------

/// An agent's identity card — used for discovery and advertisement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCard {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub protocols: Vec<String>,
    pub endpoints: Vec<AgentEndpoint>,
    pub authentication: Option<AuthScheme>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl AgentCard {
    /// Serialize the card to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize a card from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, A2AError> {
        serde_json::from_str(s).map_err(|e| A2AError::Serialization(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// A2AMessageType
// ---------------------------------------------------------------------------

/// The type of an A2A protocol message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum A2AMessageType {
    Discover,
    Advertise(AgentCard),
    Query { intent: String },
    Response { result: String },
    Delegate { task: String, target: String },
    Notify { event: String },
    Subscribe { topics: Vec<String> },
    Unsubscribe,
    Heartbeat,
    Error { code: u32, message: String },
}

// ---------------------------------------------------------------------------
// A2APayload
// ---------------------------------------------------------------------------

/// Flexible message payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum A2APayload {
    Text(String),
    Json(String),
    #[serde(
        serialize_with = "serialize_binary",
        deserialize_with = "deserialize_binary"
    )]
    Binary(Vec<u8>),
    MultiPart(Vec<A2APayload>),
}

fn serialize_binary<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(data))
}

fn deserialize_binary<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    hex::decode(s).map_err(serde::de::Error::custom)
}

impl A2APayload {
    /// Extract text content, if this is a `Text` payload.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            A2APayload::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Attempt to deserialize JSON content into a typed value.
    pub fn as_json<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        match self {
            A2APayload::Json(s) => serde_json::from_str(s).ok(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// A2AMessage
// ---------------------------------------------------------------------------

/// A single protocol message exchanged between agents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2AMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    pub message_type: A2AMessageType,
    pub payload: A2APayload,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    pub timestamp: u64,
    #[serde(default)]
    pub ttl: Option<u64>,
    #[serde(default)]
    pub signature: Option<String>,
}

impl A2AMessage {
    /// Return a canonical string of the fields that participate in signing.
    fn signing_payload(&self) -> String {
        // We exclude `signature` itself from the signed data.
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.id,
            self.from,
            self.to,
            serde_json::to_string(&self.message_type).unwrap_or_default(),
            serde_json::to_string(&self.payload).unwrap_or_default(),
            self.timestamp,
        )
    }

    /// Sign this message in-place with an HMAC-SHA256 key.
    pub fn sign(&mut self, key: &[u8]) {
        let data = self.signing_payload();
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key error");
        mac.update(data.as_bytes());
        self.signature = Some(hex::encode(mac.finalize().into_bytes()));
    }

    /// Verify the HMAC signature on this message.
    pub fn verify(&self, key: &[u8]) -> bool {
        let sig = match &self.signature {
            Some(s) => s.clone(),
            None => return false,
        };
        let data = self.signing_payload();
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key error");
        mac.update(data.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        let sig_bytes = hex::decode(&sig).unwrap_or_default();
        let expected_bytes = hex::decode(&expected).unwrap_or_default();
        if sig_bytes.len() != expected_bytes.len() {
            return false;
        }
        let mut acc: u8 = 0;
        for (a, b) in sig_bytes.iter().zip(expected_bytes.iter()) {
            acc |= a ^ b;
        }
        acc == 0
    }
}

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

/// The state of an agent session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Idle,
    Closed,
    Error(String),
}

// ---------------------------------------------------------------------------
// A2ASession
// ---------------------------------------------------------------------------

/// A conversation session between two or more agents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2ASession {
    pub session_id: String,
    pub participants: Vec<String>,
    pub messages: Vec<A2AMessage>,
    pub state: SessionState,
}

impl A2ASession {
    /// Create a new active session.
    pub fn new(session_id: String, participants: Vec<String>) -> Self {
        Self {
            session_id,
            participants,
            messages: Vec::new(),
            state: SessionState::Active,
        }
    }

    /// Append a message to the session history.
    pub fn add_message(&mut self, message: A2AMessage) {
        self.messages.push(message);
        if self.state == SessionState::Idle {
            self.state = SessionState::Active;
        }
    }

    /// Return the full message history.
    pub fn history(&self) -> &[A2AMessage] {
        &self.messages
    }

    /// Whether the session is still active or idle (i.e. not closed/error).
    pub fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active | SessionState::Idle)
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }
}

// ---------------------------------------------------------------------------
// A2ARouter
// ---------------------------------------------------------------------------

/// Routes messages between agents, manages discovery and subscriptions.
#[derive(Debug, Clone, Default)]
pub struct A2ARouter {
    agents: HashMap<String, AgentCard>,
    routes: HashMap<String, Vec<String>>, // topic → subscriber agent IDs
}

impl A2ARouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an agent by its card.
    pub fn register_agent(&mut self, card: AgentCard) {
        self.agents.insert(card.id.clone(), card);
    }

    /// Remove an agent and all its topic subscriptions.
    pub fn unregister_agent(&mut self, id: &str) {
        self.agents.remove(id);
        for subs in self.routes.values_mut() {
            subs.retain(|s| s != id);
        }
    }

    /// Subscribe an agent to a set of topics.
    pub fn subscribe(&mut self, agent_id: &str, topics: &[String]) {
        for topic in topics {
            self.routes
                .entry(topic.clone())
                .or_default()
                .push(agent_id.to_string());
        }
    }

    /// Remove an agent's subscriptions for the given topics.
    pub fn unsubscribe(&mut self, agent_id: &str, topics: &[String]) {
        for topic in topics {
            if let Some(subs) = self.routes.get_mut(topic) {
                subs.retain(|s| s != agent_id);
            }
        }
    }

    /// Resolve target agent IDs for a message.
    ///
    /// - If `to` is a specific agent ID that is registered, returns `[to]`.
    /// - If `to` matches a subscribed topic, returns all subscribers.
    /// - Otherwise returns an empty vec.
    pub fn route(&self, message: &A2AMessage) -> Vec<String> {
        if self.agents.contains_key(&message.to) {
            return vec![message.to.clone()];
        }
        if let Some(subs) = self.routes.get(&message.to) {
            return subs.clone();
        }
        Vec::new()
    }

    /// Find agents that declare a specific capability.
    pub fn find_by_capability(&self, capability: &str) -> Vec<&AgentCard> {
        self.agents
            .values()
            .filter(|c| c.capabilities.iter().any(|cap| cap == capability))
            .collect()
    }

    /// Find agents that support a specific protocol.
    pub fn find_by_protocol(&self, protocol: &str) -> Vec<&AgentCard> {
        self.agents
            .values()
            .filter(|c| c.protocols.iter().any(|p| p == protocol))
            .collect()
    }

    /// Fuzzy discovery: search name, description, and capabilities for a query.
    pub fn discover(&self, query: &str) -> Vec<&AgentCard> {
        let q = query.to_lowercase();
        self.agents
            .values()
            .filter(|c| {
                c.name.to_lowercase().contains(&q)
                    || c.description.to_lowercase().contains(&q)
                    || c.capabilities
                        .iter()
                        .any(|cap| cap.to_lowercase().contains(&q))
            })
            .collect()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_card(id: &str, name: &str) -> AgentCard {
        AgentCard {
            id: id.to_string(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: format!("Agent {name}"),
            capabilities: vec!["chat".to_string()],
            protocols: vec!["https".to_string()],
            endpoints: vec![AgentEndpoint {
                url: format!("https://{id}.example.com"),
                protocol: "https".to_string(),
                description: "main".to_string(),
            }],
            authentication: None,
            metadata: HashMap::new(),
        }
    }

    fn sample_message(from: &str, to: &str) -> A2AMessage {
        A2AMessage {
            id: "msg-1".to_string(),
            from: from.to_string(),
            to: to.to_string(),
            message_type: A2AMessageType::Query {
                intent: "hello".to_string(),
            },
            payload: A2APayload::Text("hi".to_string()),
            metadata: HashMap::new(),
            timestamp: 1000,
            ttl: Some(60),
            signature: None,
        }
    }

    // ---- AgentCard ----

    #[test]
    fn agent_card_round_trip_json() {
        let card = sample_card("a1", "Alpha");
        let json = card.to_json();
        let parsed = AgentCard::from_json(&json).unwrap();
        assert_eq!(card, parsed);
    }

    #[test]
    fn agent_card_from_invalid_json() {
        let err = AgentCard::from_json("not json").unwrap_err();
        assert!(matches!(err, A2AError::Serialization(_)));
    }

    #[test]
    fn agent_card_with_metadata() {
        let mut card = sample_card("a1", "Alpha");
        card.metadata.insert("owner".to_string(), "team-a".to_string());
        let json = card.to_json();
        let parsed = AgentCard::from_json(&json).unwrap();
        assert_eq!(parsed.metadata["owner"], "team-a");
    }

    #[test]
    fn agent_card_with_auth() {
        let mut card = sample_card("a1", "Alpha");
        card.authentication = Some(AuthScheme::ApiKey {
            header: "X-API-Key".to_string(),
        });
        let json = card.to_json();
        let parsed = AgentCard::from_json(&json).unwrap();
        assert_eq!(
            parsed.authentication,
            Some(AuthScheme::ApiKey {
                header: "X-API-Key".to_string()
            })
        );
    }

    // ---- AuthScheme ----

    #[test]
    fn auth_scheme_variants_serialize() {
        let schemes = vec![
            AuthScheme::None,
            AuthScheme::ApiKey {
                header: "X-Key".to_string(),
            },
            AuthScheme::OAuth2 {
                scopes: vec!["read".to_string()],
            },
            AuthScheme::MutualTLS,
            AuthScheme::Custom("jwt".to_string()),
        ];
        for scheme in &schemes {
            let json = serde_json::to_string(scheme).unwrap();
            let back: AuthScheme = serde_json::from_str(&json).unwrap();
            assert_eq!(*scheme, back);
        }
    }

    // ---- A2APayload ----

    #[test]
    fn payload_text() {
        let p = A2APayload::Text("hello".to_string());
        assert_eq!(p.as_text(), Some("hello"));
    }

    #[test]
    fn payload_json_typed() {
        #[derive(Deserialize, Serialize, PartialEq, Debug)]
        struct Data {
            x: i32,
        }
        let p = A2APayload::Json(r#"{"x":42}"#.to_string());
        assert_eq!(p.as_json::<Data>(), Some(Data { x: 42 }));
    }

    #[test]
    fn payload_binary_round_trip() {
        let p = A2APayload::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let json = serde_json::to_string(&p).unwrap();
        let back: A2APayload = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn payload_multipart() {
        let mp = A2APayload::MultiPart(vec![
            A2APayload::Text("a".to_string()),
            A2APayload::Binary(vec![1, 2, 3]),
        ]);
        let json = serde_json::to_string(&mp).unwrap();
        let back: A2APayload = serde_json::from_str(&json).unwrap();
        assert_eq!(mp, back);
    }

    #[test]
    fn payload_as_text_non_text_returns_none() {
        let p = A2APayload::Binary(vec![]);
        assert!(p.as_text().is_none());
    }

    #[test]
    fn payload_as_json_invalid_returns_none() {
        let p = A2APayload::Json("not valid json!!!".to_string());
        let result: Option<serde_json::Value> = p.as_json();
        assert!(result.is_none());
    }

    #[test]
    fn payload_as_json_non_json_returns_none() {
        let p = A2APayload::Text("{}".to_string());
        let result: Option<serde_json::Value> = p.as_json();
        assert!(result.is_none());
    }

    // ---- A2AMessage signing ----

    #[test]
    fn sign_and_verify_message() {
        let key = b"super-secret-key";
        let mut msg = sample_message("a1", "a2");
        assert!(!msg.verify(key));
        msg.sign(key);
        assert!(msg.verify(key));
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let key = b"correct-key";
        let wrong_key = b"wrong-key";
        let mut msg = sample_message("a1", "a2");
        msg.sign(key);
        assert!(!msg.verify(wrong_key));
    }

    #[test]
    fn verify_fails_unsigned() {
        let msg = sample_message("a1", "a2");
        assert!(!msg.verify(b"any-key"));
    }

    #[test]
    fn sign_twice_overwrites() {
        let key = b"key";
        let mut msg = sample_message("a1", "a2");
        msg.sign(key);
        let sig1 = msg.signature.clone();
        msg.sign(key);
        // Same content → same signature
        assert_eq!(sig1, msg.signature);
    }

    #[test]
    fn tampered_message_fails_verify() {
        let key = b"key";
        let mut msg = sample_message("a1", "a2");
        msg.sign(key);
        msg.payload = A2APayload::Text("tampered".to_string());
        assert!(!msg.verify(key));
    }

    // ---- A2AMessageType ----

    #[test]
    fn message_type_round_trip() {
        let types = vec![
            A2AMessageType::Discover,
            A2AMessageType::Advertise(sample_card("x", "X")),
            A2AMessageType::Query {
                intent: "search".to_string(),
            },
            A2AMessageType::Response {
                result: "found".to_string(),
            },
            A2AMessageType::Delegate {
                task: "compute".to_string(),
                target: "agent-2".to_string(),
            },
            A2AMessageType::Notify {
                event: "done".to_string(),
            },
            A2AMessageType::Subscribe {
                topics: vec!["alerts".to_string()],
            },
            A2AMessageType::Unsubscribe,
            A2AMessageType::Heartbeat,
            A2AMessageType::Error {
                code: 404,
                message: "not found".to_string(),
            },
        ];
        for mt in &types {
            let json = serde_json::to_string(mt).unwrap();
            let back: A2AMessageType = serde_json::from_str(&json).unwrap();
            assert_eq!(*mt, back);
        }
    }

    // ---- A2AMessage serialization ----

    #[test]
    fn message_json_round_trip() {
        let msg = sample_message("a1", "a2");
        let json = serde_json::to_string(&msg).unwrap();
        let back: A2AMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn message_with_ttl_none() {
        let mut msg = sample_message("a1", "a2");
        msg.ttl = None;
        let json = serde_json::to_string(&msg).unwrap();
        let back: A2AMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ttl, None);
    }

    // ---- SessionState ----

    #[test]
    fn session_state_round_trip() {
        let states = vec![
            SessionState::Active,
            SessionState::Idle,
            SessionState::Closed,
            SessionState::Error("boom".to_string()),
        ];
        for s in &states {
            let json = serde_json::to_string(s).unwrap();
            let back: SessionState = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // ---- A2ASession ----

    #[test]
    fn session_new_is_active() {
        let s = A2ASession::new("s1".to_string(), vec!["a1".to_string(), "a2".to_string()]);
        assert!(s.is_active());
        assert_eq!(s.history().len(), 0);
    }

    #[test]
    fn session_add_message() {
        let mut s = A2ASession::new("s1".to_string(), vec!["a1".to_string()]);
        s.add_message(sample_message("a1", "a2"));
        assert_eq!(s.history().len(), 1);
    }

    #[test]
    fn session_close() {
        let mut s = A2ASession::new("s1".to_string(), vec!["a1".to_string()]);
        s.close();
        assert!(!s.is_active());
        assert_eq!(s.state, SessionState::Closed);
    }

    #[test]
    fn session_idle_reactivates_on_message() {
        let mut s = A2ASession::new("s1".to_string(), vec!["a1".to_string()]);
        s.state = SessionState::Idle;
        assert!(s.is_active());
        s.add_message(sample_message("a1", "a2"));
        assert_eq!(s.state, SessionState::Active);
    }

    #[test]
    fn session_closed_stays_closed_on_message() {
        let mut s = A2ASession::new("s1".to_string(), vec!["a1".to_string()]);
        s.close();
        s.add_message(sample_message("a1", "a2"));
        // state remains Closed (add_message only changes Idle→Active)
        assert_eq!(s.state, SessionState::Closed);
    }

    #[test]
    fn session_serialization_round_trip() {
        let mut s = A2ASession::new("s1".to_string(), vec!["a1".to_string(), "a2".to_string()]);
        s.add_message(sample_message("a1", "a2"));
        let json = serde_json::to_string(&s).unwrap();
        let back: A2ASession = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // ---- A2ARouter ----

    #[test]
    fn router_register_and_unregister() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Alpha"));
        assert_eq!(router.agents.len(), 1);
        router.unregister_agent("a1");
        assert_eq!(router.agents.len(), 0);
    }

    #[test]
    fn router_route_direct() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Alpha"));
        router.register_agent(sample_card("a2", "Beta"));
        let msg = sample_message("a1", "a2");
        assert_eq!(router.route(&msg), vec!["a2"]);
    }

    #[test]
    fn router_route_topic() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Alpha"));
        router.register_agent(sample_card("a2", "Beta"));
        router.subscribe("a2", &["alerts".to_string()]);
        let msg = A2AMessage {
            to: "alerts".to_string(),
            ..sample_message("a1", "alerts")
        };
        assert_eq!(router.route(&msg), vec!["a2"]);
    }

    #[test]
    fn router_route_no_match() {
        let router = A2ARouter::new();
        let msg = sample_message("a1", "unknown");
        assert!(router.route(&msg).is_empty());
    }

    #[test]
    fn router_subscribe_and_unsubscribe() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Alpha"));
        router.subscribe("a1", &["alerts".to_string(), "logs".to_string()]);
        assert_eq!(router.routes["alerts"], vec!["a1"]);
        assert_eq!(router.routes["logs"], vec!["a1"]);
        router.unsubscribe("a1", &["alerts".to_string()]);
        assert!(router.routes["alerts"].is_empty());
        assert_eq!(router.routes["logs"], vec!["a1"]);
    }

    #[test]
    fn router_unregister_removes_subscriptions() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Alpha"));
        router.subscribe("a1", &["alerts".to_string()]);
        router.unregister_agent("a1");
        assert!(router.routes["alerts"].is_empty());
    }

    #[test]
    fn router_find_by_capability() {
        let mut router = A2ARouter::new();
        let mut card = sample_card("a1", "Alpha");
        card.capabilities = vec!["translation".to_string(), "summarization".to_string()];
        router.register_agent(card);
        router.register_agent(sample_card("a2", "Beta")); // only "chat"
        let found = router.find_by_capability("translation");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "a1");
    }

    #[test]
    fn router_find_by_capability_empty() {
        let router = A2ARouter::new();
        assert!(router.find_by_capability("anything").is_empty());
    }

    #[test]
    fn router_find_by_protocol() {
        let mut router = A2ARouter::new();
        let mut card = sample_card("a1", "Alpha");
        card.protocols = vec!["grpc".to_string()];
        router.register_agent(card);
        router.register_agent(sample_card("a2", "Beta")); // "https"
        let found = router.find_by_protocol("grpc");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "a1");
    }

    #[test]
    fn router_discover_by_name() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Translator"));
        router.register_agent(sample_card("a2", "Summarizer"));
        let found = router.discover("trans");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "a1");
    }

    #[test]
    fn router_discover_by_description() {
        let mut router = A2ARouter::new();
        router.register_agent(AgentCard {
            description: "A powerful translation engine".to_string(),
            ..sample_card("a1", "Bot")
        });
        let found = router.discover("powerful");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn router_discover_by_capability() {
        let mut router = A2ARouter::new();
        let mut card = sample_card("a1", "Bot");
        card.capabilities = vec!["image-generation".to_string()];
        router.register_agent(card);
        let found = router.discover("image");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn router_discover_case_insensitive() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "TranslatorBot"));
        assert_eq!(router.discover("TRANSLATOR").len(), 1);
        assert_eq!(router.discover("translatorbot").len(), 1);
    }

    #[test]
    fn router_discover_no_match() {
        let router = A2ARouter::new();
        assert!(router.discover("anything").is_empty());
    }

    // ---- Multi-agent routing ----

    #[test]
    fn multi_agent_topic_broadcast() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Alpha"));
        router.register_agent(sample_card("a2", "Beta"));
        router.register_agent(sample_card("a3", "Gamma"));
        router.subscribe("a1", &["events".to_string()]);
        router.subscribe("a2", &["events".to_string()]);
        let msg = A2AMessage {
            to: "events".to_string(),
            ..sample_message("a3", "events")
        };
        let targets = router.route(&msg);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&"a1".to_string()));
        assert!(targets.contains(&"a2".to_string()));
    }

    #[test]
    fn multi_agent_session() {
        let mut session = A2ASession::new(
            "room-1".to_string(),
            vec!["a1".to_string(), "a2".to_string(), "a3".to_string()],
        );
        session.add_message(sample_message("a1", "a2"));
        session.add_message(sample_message("a2", "a1"));
        session.add_message(sample_message("a3", "a1"));
        assert_eq!(session.history().len(), 3);
    }

    // ---- A2AError display ----

    #[test]
    fn error_display() {
        assert_eq!(
            A2AError::AgentNotFound("x".to_string()).to_string(),
            "agent not found: x"
        );
        assert_eq!(A2AError::Timeout.to_string(), "timeout");
        assert_eq!(
            A2AError::Serialization("bad".to_string()).to_string(),
            "serialization error: bad"
        );
    }

    // ---- Edge cases ----

    #[test]
    fn message_with_all_metadata() {
        let mut meta = HashMap::new();
        meta.insert("trace_id".to_string(), "abc-123".to_string());
        let mut msg = sample_message("a1", "a2");
        msg.metadata = meta;
        let json = serde_json::to_string(&msg).unwrap();
        let back: A2AMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.metadata["trace_id"], "abc-123");
    }

    #[test]
    fn empty_router_operations() {
        let mut router = A2ARouter::new();
        router.unsubscribe("ghost", &["topic".to_string()]);
        router.unregister_agent("ghost");
        assert!(router.find_by_capability("x").is_empty());
        assert!(router.find_by_protocol("y").is_empty());
        assert!(router.discover("z").is_empty());
    }

    #[test]
    fn agent_card_with_all_endpoints() {
        let card = AgentCard {
            id: "multi".to_string(),
            name: "MultiEndpoint".to_string(),
            version: "2.0.0".to_string(),
            description: "multi-endpoint agent".to_string(),
            capabilities: vec!["everything".to_string()],
            protocols: vec!["https".to_string(), "grpc".to_string(), "stdio".to_string()],
            endpoints: vec![
                AgentEndpoint {
                    url: "https://api.example.com".to_string(),
                    protocol: "https".to_string(),
                    description: "REST API".to_string(),
                },
                AgentEndpoint {
                    url: "grpc://api.example.com:443".to_string(),
                    protocol: "grpc".to_string(),
                    description: "gRPC".to_string(),
                },
                AgentEndpoint {
                    url: "local://".to_string(),
                    protocol: "stdio".to_string(),
                    description: "stdin/stdout".to_string(),
                },
            ],
            authentication: Some(AuthScheme::OAuth2 {
                scopes: vec!["read".to_string(), "write".to_string()],
            }),
            metadata: {
                let mut m = HashMap::new();
                m.insert("region".to_string(), "us-west".to_string());
                m
            },
        };
        let json = card.to_json();
        let back = AgentCard::from_json(&json).unwrap();
        assert_eq!(card, back);
        assert_eq!(back.endpoints.len(), 3);
    }

    #[test]
    fn payload_text_from_json_roundtrip() {
        let msg = A2AMessage {
            id: "m1".to_string(),
            from: "a".to_string(),
            to: "b".to_string(),
            message_type: A2AMessageType::Response {
                result: "ok".to_string(),
            },
            payload: A2APayload::Text("response body".to_string()),
            metadata: HashMap::new(),
            timestamp: 42,
            ttl: None,
            signature: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: A2AMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn router_register_overwrites() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Alpha"));
        let mut card2 = sample_card("a1", "AlphaV2");
        card2.version = "2.0.0".to_string();
        router.register_agent(card2);
        assert_eq!(router.agents.len(), 1);
        assert_eq!(router.agents["a1"].version, "2.0.0");
    }

    #[test]
    fn subscribe_multiple_agents_same_topic() {
        let mut router = A2ARouter::new();
        router.register_agent(sample_card("a1", "Alpha"));
        router.register_agent(sample_card("a2", "Beta"));
        router.register_agent(sample_card("a3", "Gamma"));
        router.subscribe("a1", &["news".to_string()]);
        router.subscribe("a2", &["news".to_string()]);
        router.subscribe("a3", &["news".to_string()]);
        assert_eq!(router.routes["news"].len(), 3);
    }

    #[test]
    fn session_error_state_not_active() {
        let mut s = A2ASession::new("s1".to_string(), vec!["a1".to_string()]);
        s.state = SessionState::Error("crashed".to_string());
        assert!(!s.is_active());
    }

    #[test]
    fn delegate_message_type() {
        let mt = A2AMessageType::Delegate {
            task: "translate document".to_string(),
            target: "translator-agent".to_string(),
        };
        let json = serde_json::to_string(&mt).unwrap();
        let back: A2AMessageType = serde_json::from_str(&json).unwrap();
        assert_eq!(mt, back);
    }

    #[test]
    fn notify_message_type() {
        let mt = A2AMessageType::Notify {
            event: "task.completed".to_string(),
        };
        let json = serde_json::to_string(&mt).unwrap();
        let back: A2AMessageType = serde_json::from_str(&json).unwrap();
        assert_eq!(mt, back);
    }

    #[test]
    fn full_message_sign_verify_flow() {
        let key = b"test-hmac-key-123";
        let mut msg = A2AMessage {
            id: "msg-full".to_string(),
            from: "agent-a".to_string(),
            to: "agent-b".to_string(),
            message_type: A2AMessageType::Delegate {
                task: "compute primes".to_string(),
                target: "math-agent".to_string(),
            },
            payload: A2APayload::Json(r#"{"n":1000}"#.to_string()),
            metadata: {
                let mut m = HashMap::new();
                m.insert("priority".to_string(), "high".to_string());
                m
            },
            timestamp: 9999,
            ttl: Some(120),
            signature: None,
        };
        msg.sign(key);
        assert!(msg.verify(key));

        // Serialize, deserialize, still verifies
        let json = serde_json::to_string(&msg).unwrap();
        let back: A2AMessage = serde_json::from_str(&json).unwrap();
        assert!(back.verify(key));
    }
}
