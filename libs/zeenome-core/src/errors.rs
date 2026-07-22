use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZeenomeError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Bincode error: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("MMR error: {0}")]
    Mmr(String),

    #[error("Merkle tree error: {0}")]
    Merkle(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Panel extraction produced a VCF that does not support a conclusive attestation
    /// (missing loci, no-calls, REF/ALT mismatch, or too few sites to build a Merkle tree).
    #[error("Panel inconclusive: {0}")]
    PanelInconclusive(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),
}

pub type Result<T> = std::result::Result<T, ZeenomeError>;
