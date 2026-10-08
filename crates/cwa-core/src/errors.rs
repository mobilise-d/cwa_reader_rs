#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSide {
    Left,
    Right,
}

#[derive(Debug)]
pub enum CwaError {
    Io(std::io::Error),
    InsufficientContext {
        side: ContextSide,
        owned_packets: std::ops::Range<usize>,
        loaded_packets: std::ops::Range<usize>,
        reason: &'static str,
    },
    String(String),
}

impl std::error::Error for CwaError {}

impl From<std::io::Error> for CwaError {
    fn from(err: std::io::Error) -> Self {
        CwaError::Io(err)
    }
}

impl From<&str> for CwaError {
    fn from(err: &str) -> Self {
        CwaError::String(err.to_string())
    }
}

impl From<String> for CwaError {
    fn from(err: String) -> Self {
        CwaError::String(err)
    }
}

impl From<csv::Error> for CwaError {
    fn from(err: csv::Error) -> Self {
        CwaError::String(err.to_string())
    }
}

impl std::fmt::Display for CwaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CwaError::Io(e) => write!(f, "IO error: {}", e),
            CwaError::InsufficientContext { side, owned_packets, loaded_packets, reason } => write!(f,
                "InsufficientContext: {side:?} context for owned packets {owned_packets:?} in loaded packets {loaded_packets:?}: {reason}; increase overlap_packets"),
            CwaError::String(s) => write!(f, "{}", s),
        }
    }
}
