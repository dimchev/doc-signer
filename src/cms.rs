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
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const OID_SIGNATURE_TIME_STAMP: &str = "1.2.840.113549.1.9.16.2.14";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

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

pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

pub(crate) fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

/// Unsigned big-endian magnitude -> DER INTEGER.
pub(crate) fn uint(be: &[u8]) -> Vec<u8> {
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

pub(crate) fn oid(s: &str) -> Vec<u8> {
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
/// PAdES forbids the signing-time attribute (the time is in the signature dictionary).
pub fn signed_attributes(content_digest: &[u8], cert_der: &[u8]) -> Vec<u8> {
    signed_attributes_at(content_digest, cert_der, None)
}

/// RFC 5652 Time: UTCTime for 1950-2049, GeneralizedTime otherwise.
fn der_time(t: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    use chrono::Datelike;
    if (1950..2050).contains(&t.year()) {
        tlv(0x17, t.format("%y%m%d%H%M%SZ").to_string().as_bytes())
    } else {
        tlv(0x18, t.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
    }
}

/// Signed attributes with an optional signing-time (CAdES-B requires it).
pub fn signed_attributes_at(content_digest: &[u8], cert_der: &[u8], signing_time: Option<chrono::DateTime<chrono::Utc>>) -> Vec<u8> {
    let content_type = seq(&[&oid(OID_CONTENT_TYPE), &set(&[&oid(OID_DATA)])]);
    let message_digest = seq(&[&oid(OID_MESSAGE_DIGEST), &set(&[&octet(content_digest)])]);
    let cert_hash = Sha256::digest(cert_der);
    // RFC 5035: SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, policies OPTIONAL }
    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256 (omitted), certHash OCTET STRING, ... }
    let ess_cert_id = seq(&[&octet(&cert_hash)]);
    let signing_cert = seq(&[&seq(&[&ess_cert_id])]);
    let signing_cert_attr = seq(&[&oid(OID_SIGNING_CERT_V2), &set(&[&signing_cert])]);

    let mut attrs = vec![content_type, message_digest, signing_cert_attr];
    if let Some(t) = signing_time {
        attrs.push(seq(&[&oid(OID_SIGNING_TIME), &set(&[&der_time(t)])]));
    }
    attrs.sort();
    let refs: Vec<&[u8]> = attrs.iter().map(|a| a.as_slice()).collect();
    set(&refs)
}

/// NCrypt returns ECDSA signatures as r||s; CMS wants SEQUENCE { r INTEGER, s INTEGER }.
pub(crate) fn ecdsa_raw_to_der(raw: &[u8]) -> Vec<u8> {
    let (r, s) = raw.split_at(raw.len() / 2);
    seq(&[&uint(r), &uint(s)])
}

/// The SignerInfo `signature` value as it is embedded (ECDSA r||s becomes DER); the RFC 3161
/// timestamp is taken over exactly these bytes.
pub fn signature_value(signature: &[u8], alg: KeyAlg) -> Vec<u8> {
    match alg {
        KeyAlg::Rsa => signature.to_vec(),
        KeyAlg::Ecdsa => ecdsa_raw_to_der(signature),
    }
}

/// `timestamp_token`: an RFC 3161 TimeStampToken (ContentInfo) added as the unsigned attribute
/// id-aa-signatureTimeStampToken (CAdES-T / PAdES B-T).
pub fn build_signed_data(signed_attrs: &[u8], signature: &[u8], signer: &SignerCert, timestamp_token: Option<&[u8]>) -> Vec<u8> {
    build_signed_data_with(signed_attrs, signature, signer, timestamp_token, None)
}

/// `content`: embed the signed data (enveloping, `.p7m`); `None` = detached.
pub fn build_signed_data_with(signed_attrs: &[u8], signature: &[u8], signer: &SignerCert, timestamp_token: Option<&[u8]>, content: Option<&[u8]>) -> Vec<u8> {
    let sha256 = seq(&[&oid(OID_SHA256)]);
    let sig_value = signature_value(signature, signer.alg);
    let sig_alg = match signer.alg {
        KeyAlg::Rsa => seq(&[&oid(OID_RSA), &[0x05, 0x00]]),
        KeyAlg::Ecdsa => seq(&[&oid(OID_ECDSA_SHA256)]),
    };
    let mut attrs_implicit = signed_attrs.to_vec();
    attrs_implicit[0] = 0xA0;

    let sid = seq(&[&signer.issuer_der, &uint(&signer.serial_be)]);
    let unsigned = timestamp_token.map(|tok| tlv(0xA1, &seq(&[&oid(OID_SIGNATURE_TIME_STAMP), &set(&[tok])]))).unwrap_or_default();
    let signer_info = seq(&[
        &uint(&[1]),
        &sid,
        &sha256,
        &attrs_implicit,
        &sig_alg,
        &octet(&sig_value),
        &unsigned,
    ]);
    let certs = tlv(0xA0, &signer.chain.concat());
    let signed_data = seq(&[
        &uint(&[1]),
        &set(&[&sha256]),
        &match content {
            Some(c) => seq(&[&oid(OID_DATA), &tlv(0xA0, &octet(c))]),
            None => seq(&[&oid(OID_DATA)]),
        },
        &certs,
        &set(&[&signer_info]),
    ]);
    seq(&[&oid(OID_SIGNED_DATA), &tlv(0xA0, &signed_data)])
}

// ---------- reading SignedData ----------

/// The whole TLV (tag, length and content) at the front of `b`.
pub fn tlv_bytes(b: &[u8]) -> Option<&[u8]> {
    let (_, _, rest) = read_tlv(b)?;
    Some(&b[..b.len() - rest.len()])
}

/// Certificates and the SignerInfos SET content of a ContentInfo(SignedData).
fn signed_data_parts(content_info: &[u8]) -> Option<(Vec<&[u8]>, &[u8])> {
    let (_, ci, _) = read_tlv(content_info).filter(|t| t.0 == 0x30)?;
    let (_, _, ci) = read_tlv(ci).filter(|t| t.0 == 0x06)?;
    let (_, sd, _) = read_tlv(ci).filter(|t| t.0 == 0xA0)?;
    let (_, sd, _) = read_tlv(sd).filter(|t| t.0 == 0x30)?;
    let (_, _, r) = read_tlv(sd)?; // version
    let (_, _, r) = read_tlv(r)?; // digestAlgorithms
    let (_, _, mut r) = read_tlv(r)?; // encapContentInfo
    let mut certs = Vec::new();
    if r.first() == Some(&0xA0) {
        let (_, mut list, rest) = read_tlv(r)?;
        while let Some(c) = tlv_bytes(list) {
            certs.push(c);
            list = &list[c.len()..];
        }
        r = rest;
    }
    if r.first() == Some(&0xA1) {
        r = read_tlv(r)?.2; // crls
    }
    let (_, signer_infos, _) = read_tlv(r).filter(|t| t.0 == 0x31)?;
    Some((certs, signer_infos))
}

/// Certificates embedded in a CMS ContentInfo(SignedData).
pub fn certificates(content_info: &[u8]) -> Vec<Vec<u8>> {
    signed_data_parts(content_info).map(|(c, _)| c.into_iter().map(<[u8]>::to_vec).collect()).unwrap_or_default()
}

/// RFC 3161 tokens in an unsigned-attributes list (content of `[1]`).
pub fn timestamp_tokens_in(mut attrs: &[u8]) -> Vec<Vec<u8>> {
    let ts_oid = oid(OID_SIGNATURE_TIME_STAMP);
    let mut out = Vec::new();
    while let Some((_, attr, more_attrs)) = read_tlv(attrs) {
        if let Some((_, values, _)) = attr.starts_with(&ts_oid).then(|| read_tlv(&attr[ts_oid.len()..])).flatten() {
            let mut values = values;
            while let Some(token) = tlv_bytes(values) {
                out.push(token.to_vec());
                values = &values[token.len()..];
            }
        }
        attrs = more_attrs;
    }
    out
}

/// RFC 3161 tokens in the unsigned attributes of every SignerInfo.
pub fn timestamp_tokens(content_info: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some((_, mut infos)) = signed_data_parts(content_info) else { return out };
    while let Some((_, info, more)) = read_tlv(infos) {
        let mut fields = info;
        while let Some((tag, v, next)) = read_tlv(fields) {
            if tag == 0xA1 {
                out.extend(timestamp_tokens_in(v));
            }
            fields = next;
        }
        infos = more;
    }
    out
}

/// Certificates of a signature and of its time-stamp tokens.
pub fn all_certificates(content_info: &[u8]) -> Vec<Vec<u8>> {
    let mut out = certificates(content_info);
    for token in timestamp_tokens(content_info) {
        out.extend(certificates(&token));
    }
    out
}

// ---------- RFC 3161 time-stamp protocol ----------

/// Splits one DER TLV off the front: (tag, content, remainder).
pub fn read_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
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

/// TimeStampReq (v1) for a SHA-256 `digest`, with `nonce` and certReq = TRUE.
pub fn timestamp_request(digest: &[u8], nonce: &[u8]) -> Vec<u8> {
    let imprint = seq(&[&seq(&[&oid(OID_SHA256), &[0x05, 0x00]]), &octet(digest)]);
    seq(&[&uint(&[1]), &imprint, &uint(nonce), &[0x01, 0x01, 0xFF]])
}

/// Unsigned big-endian magnitude of a DER INTEGER content (leading zero bytes removed).
fn magnitude(int: &[u8]) -> &[u8] {
    let skip = int.iter().take_while(|&&b| b == 0).count();
    &int[skip.min(int.len().saturating_sub(1))..]
}

/// A checked time-stamp response: the token to embed.
#[derive(Debug)]
pub struct TimeStamp {
    pub token: Vec<u8>,
}

/// Checks a TimeStampResp: status granted, token present, and the token's message imprint and
/// nonce match the request. The TSA's signature over the token is checked by validators.
pub fn parse_timestamp_response(resp: &[u8], digest: &[u8], nonce: &[u8]) -> Result<TimeStamp, String> {
    let bad = |what: &str| format!("invalid time-stamp response ({what})");
    let (_, body, _) = read_tlv(resp).filter(|t| t.0 == 0x30).ok_or_else(|| bad("structure"))?;
    let (_, status_info, rest) = read_tlv(body).filter(|t| t.0 == 0x30).ok_or_else(|| bad("status"))?;
    let (_, status, after_status) = read_tlv(status_info).filter(|t| t.0 == 0x02).ok_or_else(|| bad("status"))?;
    let status = status.iter().fold(0u32, |a, &b| a << 8 | b as u32);
    if status > 1 {
        // PKIFreeText (SEQUENCE OF UTF8String) may explain why.
        let text = read_tlv(after_status)
            .filter(|t| t.0 == 0x30)
            .and_then(|(_, s, _)| read_tlv(s))
            .map(|(_, t, _)| String::from_utf8_lossy(t).into_owned())
            .unwrap_or_default();
        return Err(format!("time-stamp request rejected (status {status}) {text}").trim().to_string());
    }
    if rest.is_empty() {
        return Err(bad("no token"));
    }
    let token_len = rest.len() - read_tlv(rest).ok_or_else(|| bad("token"))?.2.len();
    let token = &rest[..token_len];

    // ContentInfo { signedData, [0] SignedData { version, digestAlgs, encapContentInfo { tstInfo, [0] OCTET STRING } } }
    let (_, ci, _) = read_tlv(token).ok_or_else(|| bad("token"))?;
    let (_, _, ci) = read_tlv(ci).filter(|t| t.0 == 0x06).ok_or_else(|| bad("token"))?;
    let (_, sd, _) = read_tlv(ci).filter(|t| t.0 == 0xA0).ok_or_else(|| bad("token"))?;
    let (_, sd, _) = read_tlv(sd).filter(|t| t.0 == 0x30).ok_or_else(|| bad("token"))?;
    let (_, _, sd) = read_tlv(sd).ok_or_else(|| bad("token"))?; // version
    let (_, _, sd) = read_tlv(sd).ok_or_else(|| bad("token"))?; // digestAlgorithms
    let (_, eci, _) = read_tlv(sd).filter(|t| t.0 == 0x30).ok_or_else(|| bad("token"))?;
    let (_, ctype, eci) = read_tlv(eci).filter(|t| t.0 == 0x06).ok_or_else(|| bad("token"))?;
    if oid(OID_TST_INFO)[2..] != *ctype {
        return Err(bad("content type"));
    }
    let (_, econtent, _) = read_tlv(eci).filter(|t| t.0 == 0xA0).ok_or_else(|| bad("token"))?;
    let (_, tst, _) = read_tlv(econtent).filter(|t| t.0 == 0x04).ok_or_else(|| bad("TSTInfo"))?;

    // TSTInfo { version, policy, messageImprint { alg, hash }, serial, genTime, accuracy?, ordering?, nonce?, ... }
    let (_, tst, _) = read_tlv(tst).filter(|t| t.0 == 0x30).ok_or_else(|| bad("TSTInfo"))?;
    let (_, _, tst) = read_tlv(tst).ok_or_else(|| bad("TSTInfo"))?; // version
    let (_, _, tst) = read_tlv(tst).ok_or_else(|| bad("TSTInfo"))?; // policy
    let (_, imprint, tst) = read_tlv(tst).filter(|t| t.0 == 0x30).ok_or_else(|| bad("imprint"))?;
    let (_, _, imprint) = read_tlv(imprint).ok_or_else(|| bad("imprint"))?; // algorithm
    let (_, hash, _) = read_tlv(imprint).filter(|t| t.0 == 0x04).ok_or_else(|| bad("imprint"))?;
    if hash != digest {
        return Err("time-stamp is for a different hash".into());
    }
    let (_, _, tst) = read_tlv(tst).ok_or_else(|| bad("serial"))?;
    let (_, _gen_time, mut tst) = read_tlv(tst).filter(|t| t.0 == 0x18).ok_or_else(|| bad("genTime"))?;
    let mut got_nonce = None;
    while let Some((tag, v, rest)) = read_tlv(tst) {
        if tag == 0x02 {
            got_nonce = Some(v);
            break;
        }
        tst = rest;
    }
    if got_nonce.map(magnitude) != Some(magnitude(nonce)) {
        return Err("time-stamp nonce does not match".into());
    }
    Ok(TimeStamp { token: token.to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TimeStampResp as a TSA would send it (unsigned token body; signature checks are the validator's job).
    fn fake_response(digest: &[u8], nonce: &[u8], status: u8) -> Vec<u8> {
        let imprint = seq(&[&seq(&[&oid(OID_SHA256)]), &octet(digest)]);
        let tst = seq(&[&uint(&[1]), &oid("1.2.3.4"), &imprint, &uint(&[7]), &tlv(0x18, b"20261126120000Z"), &uint(nonce)]);
        let encap = seq(&[&oid(OID_TST_INFO), &tlv(0xA0, &octet(&tst))]);
        let sd = seq(&[&uint(&[3]), &set(&[&seq(&[&oid(OID_SHA256)])]), &encap, &set(&[])]);
        let token = seq(&[&oid(OID_SIGNED_DATA), &tlv(0xA0, &sd)]);
        seq(&[&seq(&[&uint(&[status])]), &token])
    }

    #[test]
    fn timestamp_response_is_checked_against_the_request() {
        let digest = [7u8; 32];
        let nonce = [0x80, 1, 2, 3];
        let req = timestamp_request(&digest, &nonce);
        assert_eq!(req[0], 0x30);
        assert!(req.windows(32).any(|w| w == digest));
        let ok = parse_timestamp_response(&fake_response(&digest, &nonce, 0), &digest, &nonce).unwrap();
        assert_eq!(read_tlv(&ok.token).unwrap().2.len(), 0, "token is exactly one TLV");
        assert!(parse_timestamp_response(&fake_response(&[8u8; 32], &nonce, 0), &digest, &nonce).is_err(), "wrong hash");
        assert!(parse_timestamp_response(&fake_response(&digest, &[9], 0), &digest, &nonce).is_err(), "wrong nonce");
        assert!(parse_timestamp_response(&fake_response(&digest, &nonce, 2), &digest, &nonce).is_err(), "rejected");
    }

    #[test]
    fn timestamp_token_becomes_an_unsigned_attribute() {
        let signer = SignerCert { der: vec![0x30, 0], issuer_der: vec![0x30, 0], serial_be: vec![1], chain: vec![], alg: KeyAlg::Rsa };
        let token = seq(&[&oid(OID_SIGNED_DATA)]);
        let with = build_signed_data(&signed_attributes(&[0; 32], b"c"), &[1; 4], &signer, Some(&token));
        let attr = tlv(0xA1, &seq(&[&oid(OID_SIGNATURE_TIME_STAMP), &set(&[&token])]));
        assert!(with.windows(attr.len()).any(|w| w == attr.as_slice()));
        let without = build_signed_data(&signed_attributes(&[0; 32], b"c"), &[1; 4], &signer, None);
        assert!(!without.windows(2).any(|w| w == [0xA1, attr[1]]));
    }

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
