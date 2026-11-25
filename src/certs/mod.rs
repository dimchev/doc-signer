//! Certificate store access and signing.
//!
//! Windows: the personal store (CurrentUser\My), private keys through CNG (NCrypt).
//! Linux: certificate files in a config folder (PKCS#12, or certificate + key pairs),
//! private keys through OpenSSL.

use chrono::{DateTime, Local};

#[derive(Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Local>,
    pub not_after: DateTime<Local>,
    pub thumbprint: Vec<u8>,
    pub doc_signing: bool,
}

impl CertInfo {
    pub fn is_valid_now(&self) -> bool {
        let now = Local::now();
        self.not_before <= now && now <= self.not_after
    }

    pub fn thumbprint_hex(&self) -> String {
        self.thumbprint.iter().map(|b| format!("{b:02X}")).collect()
    }
}

#[cfg(windows)]
pub use win::{list_certificates, load_signer, sign_digest};
#[cfg(not(windows))]
pub use nix::{list_certificates, load_signer, sign_digest};

/// Folder the certificate files are read from (Linux only).
#[cfg(not(windows))]
pub fn dir() -> std::path::PathBuf {
    nix::certs_dir()
}

#[cfg(windows)]
mod win;
#[cfg(not(windows))]
mod nix;
