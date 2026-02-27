use std::collections::HashMap;
use std::fmt;

/// AST node for SPL S-expressions.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Bool(bool),
    Number(f64),
    Str(String),
    Symbol(String),
    List(Vec<Node>),
    Nil,
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Node::Bool(true) => write!(f, "#t"),
            Node::Bool(false) => write!(f, "#f"),
            Node::Number(n) => write!(f, "{n}"),
            Node::Str(s) => write!(f, "\"{s}\""),
            Node::Symbol(s) => write!(f, "{s}"),
            Node::List(items) => {
                write!(f, "(")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 { write!(f, " ")?; }
                    write!(f, "{item}")?;
                }
                write!(f, ")")
            }
            Node::Nil => write!(f, "nil"),
        }
    }
}

impl Node {
    pub fn is_truthy(&self) -> bool {
        match self {
            Node::Bool(b) => *b,
            Node::Nil => false,
            Node::Number(n) => *n != 0.0,
            _ => true,
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            Node::Number(n) => *n,
            _ => 0.0,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Node::Str(s) | Node::Symbol(s) => Some(s),
            _ => None,
        }
    }
}

/// SPL evaluation error.
#[derive(Debug, Clone)]
pub struct SplError(pub String);

impl fmt::Display for SplError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SplError {}

pub type SplResult = Result<Node, SplError>;

type BoolCallback = Box<dyn Fn() -> bool>;
type MerkleCallback = Box<dyn Fn(&[Node]) -> bool>;
type VrfCallback = Box<dyn Fn(&str, f64) -> bool>;
type CountCallback = Box<dyn Fn(&str, &str) -> i64>;

/// Crypto callback functions provided by the host.
pub struct CryptoCallbacks {
    pub dpop_ok: BoolCallback,
    pub merkle_ok: MerkleCallback,
    pub vrf_ok: VrfCallback,
    /// thresh_ok — Threshold co-signature verification.
    /// Expected protocol: k-of-n co-signatures where the verifier checks each
    /// signature against its corresponding public key and confirms count >= threshold.
    /// Not implemented in v0.1 — remains an interface stub.
    pub thresh_ok: BoolCallback,
}

impl Default for CryptoCallbacks {
    fn default() -> Self {
        Self {
            dpop_ok: Box::new(|| false),
            merkle_ok: Box::new(|_| false),
            vrf_ok: Box::new(|_, _| false),
            thresh_ok: Box::new(|| false),
        }
    }
}

/// Evaluation environment.
pub struct Env {
    pub req: HashMap<String, Node>,
    pub vars: HashMap<String, Node>,
    pub per_day_count: CountCallback,
    pub crypto: CryptoCallbacks,
    pub max_gas: i64,
    pub sealed: bool,
    pub strict: bool,
}

impl Default for Env {
    fn default() -> Self {
        Self {
            req: HashMap::new(),
            vars: HashMap::new(),
            per_day_count: Box::new(|_, _| 0),
            crypto: CryptoCallbacks::default(),
            max_gas: 10_000,
            sealed: false,
            strict: false,
        }
    }
}
