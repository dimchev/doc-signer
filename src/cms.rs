//! Minimal DER encoder for a detached CMS SignedData (CAdES-BES / PAdES B-B).

use sha2::{Digest, Sha256};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    Rsa,
    Ecdsa,
}

/// Everything about the signer that goes into the CMS structure.
#[derive(Clone)]
pub struct SignerCert {
    pub der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub serial_be: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    pub alg: KeyAlg,
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let len = content.len();
    if len < 0x80 {
        v.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        v.push(0x80 | (bytes.len() - skip) as u8);
        v.extend_from_slice(&bytes[skip..]);
    }
    v.extend_from_slice(content);
    v
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

/// Unsigned big-endian magnitude -> DER INTEGER.
fn uint(be: &[u8]) -> Vec<u8> {
    let mut b: &[u8] = be;
    while b.len() > 1 && b[0] == 0 && b[1] < 0x80 {
        b = &b[1..];
    }
    let mut c = Vec::with_capacity(b.len() + 1);
    if b.is_empty() || b[0] >= 0x80 {
        c.push(0);
    }
    c.extend_from_slice(b);
    tlv(0x02, &c)
}

fn oid(s: &str) -> Vec<u8> {
    let arcs: Vec<u64> = s.split('.').map(|a| a.parse().unwrap()).collect();
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut tmp = vec![(a & 0x7f) as u8];
        let mut v = a >> 7;
        while v > 0 {
            tmp.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        tmp.reverse();
        out.extend(tmp);
    }
    tlv(0x06, &out)
}

/// DER `SET OF Attribute` for signed attributes; this exact encoding is what gets signed.
pub fn signed_attributes(content_digest: &[u8], cert_der: &[u8]) -> Vec<u8> {
    let content_type = seq(&[&oid(OID_CONTENT_TYPE), &set(&[&oid(OID_DATA)])]);
    let message_digest = seq(&[&oid(OID_MESSAGE_DIGEST), &set(&[&octet(content_digest)])]);
    let cert_hash = Sha256::digest(cert_der);
    // RFC 5035: SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, policies OPTIONAL }
    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256 (omitted), certHash OCTET STRING, ... }
    let ess_cert_id = seq(&[&octet(&cert_hash)]);
    let signing_cert = seq(&[&seq(&[&ess_cert_id])]);
    let signing_cert_attr = seq(&[&oid(OID_SIGNING_CERT_V2), &set(&[&signing_cert])]);

    let mut attrs = vec![content_type, message_digest, signing_cert_attr];
    attrs.sort();
    let refs: Vec<&[u8]> = attrs.iter().map(|a| a.as_slice()).collect();
    set(&refs)
}

/// NCrypt returns ECDSA signatures as r||s; CMS wants SEQUENCE { r INTEGER, s INTEGER }.
fn ecdsa_raw_to_der(raw: &[u8]) -> Vec<u8> {
    let (r, s) = raw.split_at(raw.len() / 2);
    seq(&[&uint(r), &uint(s)])
}

pub fn build_signed_data(signed_attrs: &[u8], signature: &[u8], signer: &SignerCert) -> Vec<u8> {
    let sha256 = seq(&[&oid(OID_SHA256)]);
    let (sig_alg, sig_value) = match signer.alg {
        KeyAlg::Rsa => (seq(&[&oid(OID_RSA), &[0x05, 0x00]]), signature.to_vec()),
        KeyAlg::Ecdsa => (seq(&[&oid(OID_ECDSA_SHA256)]), ecdsa_raw_to_der(signature)),
    };
    let mut attrs_implicit = signed_attrs.to_vec();
    attrs_implicit[0] = 0xA0;

    let sid = seq(&[&signer.issuer_der, &uint(&signer.serial_be)]);
    let signer_info = seq(&[
        &uint(&[1]),
        &sid,
        &sha256,
        &attrs_implicit,
        &sig_alg,
        &octet(&sig_value),
    ]);
    let certs = tlv(0xA0, &signer.chain.concat());
    let signed_data = seq(&[
        &uint(&[1]),
        &set(&[&sha256]),
        &seq(&[&oid(OID_DATA)]),
        &certs,
        &set(&[&signer_info]),
    ]);
    seq(&[&oid(OID_SIGNED_DATA), &tlv(0xA0, &signed_data)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_oid_and_lengths() {
        assert_eq!(oid("1.2.840.113549.1.7.2"), [6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2]);
        assert_eq!(&tlv(4, &[0; 200])[..3], &[4, 0x81, 200]);
        assert_eq!(&tlv(4, &[0; 300])[..4], &[4, 0x82, 1, 44]);
    }

    #[test]
    fn integers_are_positive_and_minimal() {
        assert_eq!(uint(&[0x80]), [2, 2, 0, 0x80]);
        assert_eq!(uint(&[0, 0, 0x7f]), [2, 1, 0x7f]);
        assert_eq!(uint(&[0, 0x80]), [2, 2, 0, 0x80]);
    }

    /// PAdES B-B requires the signing-certificate-v2 attribute with the RFC 5035 structure.
    #[test]
    fn signing_certificate_v2_attribute_is_rfc5035() {
        let cert = b"fake certificate der";
        let attrs = signed_attributes(&[0u8; 32], cert);
        let hash = Sha256::digest(cert);
        let ess_cert_id = seq(&[&octet(&hash)]);
        let expected = seq(&[&oid("1.2.840.113549.1.9.16.2.47"), &set(&[&seq(&[&seq(&[&ess_cert_id])])])]);
        assert!(attrs.windows(expected.len()).any(|w| w == expected.as_slice()), "signing-certificate-v2 attribute missing or malformed");
    }
}
