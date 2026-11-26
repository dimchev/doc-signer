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
pub use win::{list_certificates, load_signer, sign_data};
#[cfg(not(windows))]
pub use nix::{list_certificates, load_signer, sign_data};

/// Folder the certificate files are read from (Linux only).
#[cfg(not(windows))]
pub fn dir() -> std::path::PathBuf {
    nix::certs_dir()
}

/// True if the certificate's extendedKeyUsage extension (2.5.29.37) lists the Microsoft
/// Document Signing purpose (1.3.6.1.4.1.311.10.3.12). Walks the extension's DER structure
/// instead of searching the whole certificate for the OID bytes.
pub(crate) fn has_doc_signing_eku(cert_der: &[u8]) -> bool {
    const EKU_EXTENSION_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x25];
    const DOC_SIGNING_OID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x0C];
    let Some(pos) = cert_der.windows(EKU_EXTENSION_OID.len()).position(|w| w == EKU_EXTENSION_OID) else {
        return false;
    };
    // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    let mut rest = &cert_der[pos + EKU_EXTENSION_OID.len()..];
    if let Some((0x01, _, after)) = der_tlv(rest) {
        rest = after;
    }
    let Some((0x04, value, _)) = der_tlv(rest) else { return false };
    // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
    let Some((0x30, mut purposes, _)) = der_tlv(value) else { return false };
    while let Some((tag, oid, after)) = der_tlv(purposes) {
        if tag == 0x06 && oid == DOC_SIGNING_OID {
            return true;
        }
        purposes = after;
    }
    false
}

/// Splits one DER TLV off the front: (tag, content, remainder).
fn der_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |acc, &x| acc << 8 | x as usize), &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

#[cfg(windows)]
mod win;
#[cfg(not(windows))]
mod nix;

#[cfg(test)]
mod tests {
    use super::*;

    const CODE_SIGNING: [u8; 10] = [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    const DOC_SIGNING: [u8; 12] = [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x0C];

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, content.len() as u8];
        v.extend_from_slice(content);
        v
    }

    fn eku_extension(critical: bool, purposes: &[&[u8]]) -> Vec<u8> {
        let seq = tlv(0x30, &purposes.concat());
        let mut ext = vec![0x06, 0x03, 0x55, 0x1D, 0x25];
        if critical {
            ext.extend(tlv(0x01, &[0xFF]));
        }
        ext.extend(tlv(0x04, &seq));
        tlv(0x30, &ext)
    }

    #[test]
    fn detects_document_signing_eku() {
        assert!(has_doc_signing_eku(&eku_extension(false, &[&CODE_SIGNING, &DOC_SIGNING])));
        assert!(has_doc_signing_eku(&eku_extension(true, &[&DOC_SIGNING])));
    }

    #[test]
    fn ignores_doc_signing_oid_outside_the_eku_extension() {
        assert!(!has_doc_signing_eku(&eku_extension(false, &[&CODE_SIGNING])));
        // The OID bytes elsewhere in the certificate (e.g. a policy) must not count.
        let mut der = tlv(0x30, &DOC_SIGNING);
        der.extend(eku_extension(false, &[&CODE_SIGNING]));
        assert!(!has_doc_signing_eku(&der));
        assert!(!has_doc_signing_eku(&DOC_SIGNING));
    }
}