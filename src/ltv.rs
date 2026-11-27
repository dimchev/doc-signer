//! Validation data for long-term signatures (PAdES B-LT): the certificate chains of the signer
//! and the time-stamp authority, plus an OCSP response or a CRL for every certificate.

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use sha1::{Digest, Sha1};

use crate::cms::{self, read_tlv};
use crate::i18n::t;
use crate::x509::{self, Cert};

const OID_SHA1: &str = "1.3.14.3.2.26";
const MAX_DOWNLOAD: u64 = 32 * 1024 * 1024;

#[derive(Default, Debug)]
pub struct ValidationData {
    pub certs: Vec<Vec<u8>>,
    pub ocsps: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    /// Certificates without revocation data, revoked certificates, failed downloads.
    pub warnings: Vec<String>,
}

/// Network access, replaceable in tests.
pub trait Fetch {
    fn get(&self, url: &str) -> Result<Vec<u8>>;
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// HTTP(S) with the system proxy and trust store (as for the TSA).
pub struct Http;

fn encode_url(url: &str) -> String {
    // URLs in certificates often contain raw spaces (e.g. AD CS "CertEnroll/Root CA v2.crl").
    url.trim().replace(' ', "%20")
}

impl Fetch for Http {
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        let mut resp = crate::tsa::agent().get(&encode_url(url)).call()?;
        Ok(resp.body_mut().with_config().limit(MAX_DOWNLOAD).read_to_vec()?)
    }

    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut resp = crate::tsa::agent().post(&encode_url(url)).header("Content-Type", content_type).send(body)?;
        Ok(resp.body_mut().with_config().limit(MAX_DOWNLOAD).read_to_vec()?)
    }
}

fn http_urls(urls: &[String]) -> impl Iterator<Item = &String> {
    urls.iter().filter(|u| {
        let l = u.to_ascii_lowercase();
        l.starts_with("http://") || l.starts_with("https://")
    })
}

/// DER from DER or PEM (`-----BEGIN ...-----`) input; every PEM block is returned.
fn der_blocks(b: &[u8]) -> Vec<Vec<u8>> {
    if !b.starts_with(b"-----BEGIN") {
        return vec![b.to_vec()];
    }
    let text = String::from_utf8_lossy(b);
    let mut out = Vec::new();
    for block in text.split("-----BEGIN").skip(1) {
        let body: String = block.lines().skip(1).take_while(|l| !l.starts_with("-----END")).collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body.trim()) {
            out.push(der);
        }
    }
    out
}

/// Certificates from a caIssuers download: a DER/PEM certificate or a certs-only PKCS#7 (.p7c).
fn certs_from(b: &[u8]) -> Vec<Cert> {
    der_blocks(b)
        .into_iter()
        .flat_map(|der| match x509::parse(&der) {
            Some(c) => vec![c],
            None => cms::certificates(&der).iter().filter_map(|d| x509::parse(d)).collect(),
        })
        .collect()
}

pub fn ocsp_request(cert: &Cert, issuer: &Cert) -> Vec<u8> {
    let cert_id = cms::seq(&[
        &cms::seq(&[&cms::oid(OID_SHA1), &[0x05, 0x00]]),
        &cms::octet(&Sha1::digest(&cert.issuer)),
        &cms::octet(&Sha1::digest(&issuer.public_key)),
        &cms::tlv(0x02, &cert.serial),
    ]);
    // OCSPRequest { tbsRequest { requestList { Request { reqCert } } } }
    cms::seq(&[&cms::seq(&[&cms::seq(&[&cms::seq(&[&cert_id])])])])
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CertStatus {
    Good,
    Revoked,
    Unknown,
}

fn magnitude(int: &[u8]) -> &[u8] {
    let skip = int.iter().take_while(|&&b| b == 0).count();
    &int[skip.min(int.len().saturating_sub(1))..]
}

/// sha1WithRSAEncryption, dsa-with-sha1, ecdsa-with-SHA1: rejected by current validators.
const SHA1_SIGNATURES: [&str; 3] = ["1.2.840.113549.1.1.5", "1.2.840.10040.4.3", "1.2.840.10045.4.1"];

/// A parsed OCSP response for one certificate.
pub struct Ocsp {
    pub status: CertStatus,
    /// Certificates the responder included (its own certificate, usually).
    pub certs: Vec<Vec<u8>>,
    /// Signed with SHA-1, which long-term validation does not accept.
    pub weak: bool,
}

/// Status of `serial` in an OCSPResponse.
pub fn parse_ocsp(resp: &[u8], serial: &[u8]) -> Result<Ocsp> {
    let bad = || anyhow!("invalid OCSP response");
    let (_, r, _) = read_tlv(resp).filter(|t| t.0 == 0x30).ok_or_else(bad)?;
    let (_, status, r) = read_tlv(r).filter(|t| t.0 == 0x0A).ok_or_else(bad)?;
    if status != [0] {
        bail!("OCSP responder status {}", status.first().copied().unwrap_or(0xFF));
    }
    let (_, bytes, _) = read_tlv(r).filter(|t| t.0 == 0xA0).ok_or_else(bad)?;
    let (_, bytes, _) = read_tlv(bytes).ok_or_else(bad)?;
    let (_, _, bytes) = read_tlv(bytes).filter(|t| t.0 == 0x06).ok_or_else(bad)?;
    let (_, basic, _) = read_tlv(bytes).filter(|t| t.0 == 0x04).ok_or_else(bad)?;
    let (_, basic, _) = read_tlv(basic).filter(|t| t.0 == 0x30).ok_or_else(bad)?;
    let (_, tbs, after) = read_tlv(basic).filter(|t| t.0 == 0x30).ok_or_else(bad)?;
    let (_, sig_alg, after) = read_tlv(after).ok_or_else(bad)?;
    let weak = SHA1_SIGNATURES.iter().any(|o| sig_alg.starts_with(&cms::oid(o)));
    let (_, _, after) = read_tlv(after).ok_or_else(bad)?; // signature
    let mut certs = Vec::new();
    if let Some((0xA0, list, _)) = read_tlv(after) {
        if let Some((_, mut list, _)) = read_tlv(list) {
            while let Some(c) = cms::tlv_bytes(list) {
                certs.push(c.to_vec());
                list = &list[c.len()..];
            }
        }
    }
    let mut r = tbs;
    if r.first() == Some(&0xA0) {
        r = read_tlv(r).ok_or_else(bad)?.2; // version
    }
    let (_, _, r) = read_tlv(r).ok_or_else(bad)?; // responderID
    let (_, _, r) = read_tlv(r).filter(|t| t.0 == 0x18).ok_or_else(bad)?; // producedAt
    let (_, mut responses, _) = read_tlv(r).filter(|t| t.0 == 0x30).ok_or_else(bad)?;
    while let Some((_, single, more)) = read_tlv(responses) {
        let (_, cert_id, rest) = read_tlv(single).ok_or_else(bad)?;
        let (_, _, id) = read_tlv(cert_id).ok_or_else(bad)?; // hashAlgorithm
        let (_, _, id) = read_tlv(id).ok_or_else(bad)?; // issuerNameHash
        let (_, _, id) = read_tlv(id).ok_or_else(bad)?; // issuerKeyHash
        let (_, sn, _) = read_tlv(id).ok_or_else(bad)?;
        if magnitude(sn) == magnitude(serial) {
            let status = match rest.first() {
                Some(0x80) => CertStatus::Good,
                Some(0xA1) => CertStatus::Revoked,
                _ => CertStatus::Unknown,
            };
            return Ok(Ocsp { status, certs, weak });
        }
        responses = more;
    }
    bail!("OCSP response does not cover the certificate")
}

fn issuer_of<'a>(pool: &'a [Cert], c: &Cert) -> Option<&'a Cert> {
    pool.iter().find(|p| p.subject == c.issuer && p.der != c.der)
}

fn add(pool: &mut Vec<Cert>, c: Cert) {
    if !pool.iter().any(|p| p.der == c.der) {
        pool.push(c);
    }
}

/// Collects validation data for the given certificates (signer chain, TSA certificates).
///
/// A cross-certificate of a trusted self-signed root (`anchors`, same public key) is replaced
/// by that root: validators then end the path at the root instead of following the
/// cross-certification, where they would reject the OCSP responses signed by the root's key
/// (RFC 6960 4.2.2.2: the responder must be the issuer named in the certificate).
pub fn collect(certs: &[Vec<u8>], net: &dyn Fetch, anchors: &[Cert]) -> ValidationData {
    let mut vd = ValidationData::default();
    let mut pool: Vec<Cert> = Vec::new();
    let anchor_for = |c: &Cert| anchors.iter().find(|a| a.public_key == c.public_key && a.subject == c.subject).cloned();
    for c in certs.iter().filter_map(|d| x509::parse(d)) {
        add(&mut pool, anchor_for(&c).unwrap_or(c));
    }

    let mut i = 0;
    while i < pool.len() && i < 64 {
        let c = pool[i].clone();
        i += 1;
        if c.self_issued() {
            continue;
        }
        // Complete the chain from the AIA caIssuers URL when the issuer was not embedded.
        if issuer_of(&pool, &c).is_none() {
            for url in http_urls(&c.ca_issuer_urls) {
                if let Ok(b) = net.get(url) {
                    let found = certs_from(&b);
                    if !found.is_empty() {
                        found.into_iter().for_each(|f| add(&mut pool, anchor_for(&f).unwrap_or(f)));
                        break;
                    }
                }
            }
        }
        if c.ocsp_nocheck {
            continue;
        }
        let Some(issuer) = issuer_of(&pool, &c).cloned() else {
            vd.warnings.push(format!("{}: {}", c.name(), t().ltv_no_issuer));
            continue;
        };
        let mut done = false;
        let mut errors = Vec::new();
        // A SHA-1 signed OCSP response is kept only if no CRL can be had instead.
        let mut weak_ocsp = None;
        for url in http_urls(&c.ocsp_urls) {
            let resp = net.post(url, "application/ocsp-request", &ocsp_request(&c, &issuer));
            match resp.and_then(|r| parse_ocsp(&r, &c.serial).map(|p| (r, p))) {
                Ok((_, o)) if o.status == CertStatus::Unknown => errors.push(format!("{url}: unknown")),
                Ok((der, o)) => {
                    if o.status == CertStatus::Revoked {
                        vd.warnings.push(format!("{}: {}", c.name(), t().ltv_revoked));
                    }
                    let responder: Vec<Cert> = o.certs.iter().filter_map(|d| x509::parse(d)).collect();
                    if o.weak {
                        weak_ocsp = Some((der, responder));
                        continue;
                    }
                    vd.ocsps.push(der);
                    for rc in responder {
                        add(&mut pool, anchor_for(&rc).unwrap_or(rc));
                    }
                    done = true;
                    break;
                }
                Err(e) => errors.push(format!("{url}: {e:#}")),
            }
        }
        if !done {
            for url in http_urls(&c.crl_urls) {
                match net.get(url) {
                    Ok(b) => {
                        for der in der_blocks(&b) {
                            if !vd.crls.contains(&der) {
                                vd.crls.push(der);
                            }
                        }
                        done = true;
                        break;
                    }
                    Err(e) => errors.push(format!("{url}: {e:#}")),
                }
            }
        }
        if !done && let Some((der, responder)) = weak_ocsp {
            vd.ocsps.push(der);
            for rc in responder {
                add(&mut pool, anchor_for(&rc).unwrap_or(rc));
            }
            done = true;
        }
        if !done {
            let why = if errors.is_empty() { String::new() } else { format!(" ({})", errors.join("; ")) };
            vd.warnings.push(format!("{}: {}{why}", c.name(), t().ltv_no_revocation));
        }
    }
    vd.certs = pool.into_iter().map(|c| c.der).collect();
    vd
}

/// Turns a freshly signed PDF (B-T) into B-LT by adding the validation data of its newest
/// signature, and into B-LTA with a document time-stamp from `archive_tsa`.
/// Missing revocation data or a failed archive time-stamp are warnings, not errors.
pub fn extend(signed: &[u8], password: Option<&str>, archive_tsa: Option<&str>, net: &dyn Fetch) -> Result<(Vec<u8>, Vec<String>)> {
    let cms_der = crate::pdf::last_signature_cms(signed, password)?;
    let anchors = crate::certs::trusted_roots();
    let vd = collect(&cms::all_certificates(&cms_der), net, anchors);
    let mut out = crate::pdf::add_dss(signed, password, &vd.certs, &vd.ocsps, &vd.crls)?;
    let mut warnings = vd.warnings;
    if let Some(url) = archive_tsa {
        let ts = |digest: &[u8]| crate::tsa::timestamp_digest(url, digest).map(|t| t.token);
        match crate::pdf::add_doc_timestamp(&out, password, &ts) {
            Ok(with_ts) => {
                // The archive time-stamp's TSA certificates get validation data too, if new.
                let token = crate::pdf::last_signature_cms(&with_ts, password)?;
                let new: Vec<Vec<u8>> = cms::certificates(&token).into_iter().filter(|c| !vd.certs.contains(c)).collect();
                out = with_ts;
                if !new.is_empty() {
                    let more = collect(&[new, vd.certs.clone()].concat(), net, anchors);
                    let certs: Vec<Vec<u8>> = more.certs.into_iter().filter(|c| !vd.certs.contains(c)).collect();
                    let ocsps: Vec<Vec<u8>> = more.ocsps.into_iter().filter(|o| !vd.ocsps.contains(o)).collect();
                    let crls: Vec<Vec<u8>> = more.crls.into_iter().filter(|c| !vd.crls.contains(c)).collect();
                    if !(certs.is_empty() && ocsps.is_empty() && crls.is_empty()) {
                        out = crate::pdf::add_dss(&out, password, &certs, &ocsps, &crls)?;
                    }
                }
            }
            Err(e) => warnings.push(format!("{}: {e:#}", t().lta_failed)),
        }
    }
    Ok((out, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Fixture PKI made by scripts/make_ltv_fixtures.sh: root CA, leaf with AIA (OCSP + caIssuers)
    /// and CRL DP, OCSP responses for the leaf (good / revoked) and the root's CRL.
    fn fx(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/ltv/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    struct Mock(HashMap<&'static str, Vec<u8>>);

    impl Fetch for Mock {
        fn get(&self, url: &str) -> Result<Vec<u8>> {
            self.0.get(url).cloned().ok_or_else(|| anyhow!("offline"))
        }
        fn post(&self, url: &str, _: &str, _: &[u8]) -> Result<Vec<u8>> {
            self.get(url)
        }
    }

    const OCSP: &str = "http://127.0.0.1:8081/ocsp";
    const CRL: &str = "http://127.0.0.1:8080/root ca.crl";
    const CA: &str = "http://127.0.0.1:8080/root ca.crt";

    #[test]
    fn leaf_gets_its_issuer_and_an_ocsp_response() {
        let leaf = der_blocks(&fx("leaf.pem")).remove(0);
        let net = Mock(HashMap::from([(CA, fx("root.pem")), (OCSP, fx("ocsp-good.der"))]));
        let vd = collect(&[leaf.clone()], &net, &[]);
        assert_eq!(vd.certs.len(), 3, "leaf, root from caIssuers, OCSP responder");
        assert_eq!(vd.ocsps.len(), 1);
        assert!(vd.crls.is_empty());
        assert!(vd.warnings.is_empty(), "{:?}", vd.warnings);

        let parsed = x509::parse(&leaf).unwrap();
        let o = parse_ocsp(&vd.ocsps[0], &parsed.serial).unwrap();
        assert_eq!(o.status, CertStatus::Good);
        assert!(!o.weak, "the fixture responder signs with SHA-256");
    }

    #[test]
    fn falls_back_to_the_crl_and_reports_revocation() {
        let leaf = der_blocks(&fx("leaf.pem")).remove(0);
        let root = der_blocks(&fx("root.pem")).remove(0);
        let net = Mock(HashMap::from([(CRL, fx("root.crl"))]));
        let vd = collect(&[leaf.clone(), root.clone()], &net, &[]);
        assert_eq!((vd.ocsps.len(), vd.crls.len()), (0, 1));
        assert!(vd.warnings.is_empty(), "{:?}", vd.warnings);

        let net = Mock(HashMap::from([(OCSP, fx("ocsp-revoked.der"))]));
        let vd = collect(&[leaf.clone(), root.clone()], &net, &[]);
        assert_eq!(vd.warnings.len(), 1, "{:?}", vd.warnings);

        let vd = collect(&[leaf.clone(), root], &Mock(HashMap::new()), &[]);
        assert_eq!(vd.warnings.len(), 1, "offline: no revocation data for the leaf");
        assert_eq!(vd.certs.len(), 2);

        // A cross-certificate of a trusted root is replaced by the self-signed root.
        let mut anchor = x509::parse(&leaf).unwrap();
        anchor.issuer = anchor.subject.clone();
        anchor.der = b"self-signed twin".to_vec();
        let vd = collect(&[leaf], &Mock(HashMap::new()), &[anchor]);
        assert!(vd.warnings.is_empty() && vd.ocsps.is_empty() && vd.crls.is_empty());
        assert_eq!(vd.certs, [b"self-signed twin".to_vec()]);
    }

    #[test]
    fn ocsp_request_matches_openssl() {
        let leaf = x509::parse(&der_blocks(&fx("leaf.pem")).remove(0)).unwrap();
        let root = x509::parse(&der_blocks(&fx("root.pem")).remove(0)).unwrap();
        assert_eq!(ocsp_request(&leaf, &root), fx("ocsp-request.der"));
    }
}
