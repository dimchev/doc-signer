//! CAdES signatures over arbitrary files: detached (`.p7s`) or enveloping (`.p7m`).

use anyhow::Result;
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::cms::{self, SignerCert};
use crate::pdf::Timestamper;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// Signature in a separate `.p7s` file; the original stays untouched.
    Detached,
    /// The file is embedded in the signature (`.p7m`).
    Enveloping,
    /// All non-PDF files in one ASiC-E container (see `asic`); not a format for [`sign`].
    Asice,
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Format::Detached => "p7s",
            Format::Enveloping => "p7m",
            Format::Asice => "asice",
        }
    }

    pub fn code(self) -> &'static str {
        self.extension()
    }

    pub fn from_code(s: &str) -> Format {
        match s {
            "p7m" => Format::Enveloping,
            "asice" => Format::Asice,
            _ => Format::Detached,
        }
    }
}

/// DER CMS SignedData (CAdES-B, or CAdES-T with `timestamp`) over `data`.
pub fn sign(data: &[u8], format: Format, signer: &SignerCert, sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>, timestamp: Option<Timestamper>) -> Result<Vec<u8>> {
    let digest = Sha256::digest(data);
    let attrs = cms::signed_attributes_at(&digest, &signer.der, Some(Utc::now()));
    let signature = sign(&attrs)?;
    let token = match timestamp {
        Some(ts) => Some(ts(&cms::signature_value(&signature, signer.alg))?),
        None => None,
    };
    let content = (format == Format::Enveloping).then_some(data);
    Ok(cms::build_signed_data_with(&attrs, &signature, signer, token.as_deref(), content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::{KeyAlg, read_tlv};

    fn signer() -> SignerCert {
        SignerCert { der: vec![0x30, 0], issuer_der: vec![0x30, 0], serial_be: vec![1], chain: vec![vec![0x30, 0]], alg: KeyAlg::Rsa }
    }

    #[test]
    fn enveloping_embeds_the_content_detached_does_not() {
        let data = b"hello world, this is the signed file content";
        let fake = |_: &[u8]| Ok(vec![0xAB; 256]);
        let p7s = sign(data, Format::Detached, &signer(), &fake, None).unwrap();
        let p7m = sign(data, Format::Enveloping, &signer(), &fake, None).unwrap();
        assert!(!p7s.windows(data.len()).any(|w| w == data));
        assert!(p7m.windows(data.len()).any(|w| w == data));
        for der in [&p7s, &p7m] {
            assert_eq!(read_tlv(der).unwrap().2.len(), 0, "one complete DER structure");
        }
        // signing-time (1.2.840.113549.1.9.5) is present for CAdES.
        let oid_signing_time = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
        assert!(p7s.windows(oid_signing_time.len()).any(|w| w == oid_signing_time));
    }

    /// End-to-end with a real certificate (same variables as the PDF test): writes
    /// `<file>.p7s` and `<file>.p7m` next to `DOC_SIGNER_TEST_PDF` (signed as an ordinary file).
    /// Optional `DOC_SIGNER_TSA` adds a time-stamp (CAdES-T).
    #[test]
    #[ignore]
    fn signs_file_with_real_certificate() {
        let (Ok(input), Ok(thumb_hex)) = (std::env::var("DOC_SIGNER_TEST_PDF"), std::env::var("DOC_SIGNER_THUMB")) else {
            eprintln!("SKIPPED signs_file_with_real_certificate: set DOC_SIGNER_TEST_PDF and DOC_SIGNER_THUMB to run it");
            return;
        };
        let thumb: Vec<u8> = (0..thumb_hex.len()).step_by(2).map(|i| u8::from_str_radix(&thumb_hex[i..i + 2], 16).unwrap()).collect();
        let signer = crate::certs::load_signer(&thumb).unwrap();
        let data = std::fs::read(&input).unwrap();
        let tsa = std::env::var("DOC_SIGNER_TSA").ok();
        let ts = |v: &[u8]| crate::tsa::timestamp(tsa.as_deref().unwrap(), v).map(|t| t.token);
        let ts_ref: Option<Timestamper> = if tsa.is_some() { Some(&ts) } else { None };
        for format in [Format::Detached, Format::Enveloping] {
            let der = sign(&data, format, &signer, &|d| crate::certs::sign_data(&thumb, d, signer.alg), ts_ref).unwrap();
            std::fs::write(format!("{input}.{}", format.extension()), der).unwrap();
        }
    }
}