
#[derive(Debug)]
pub enum CwaError {
    Io(std::io::Error),
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

impl std::fmt::Display for CwaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CwaError::Io(e) => write!(f, "IO error: {}", e),
            CwaError::String(s) => write!(f, "{}", s),
        }
    }
}
