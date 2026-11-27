//! Verification of existing signatures: PDF (PAdES and document time-stamps), CAdES `.p7s` /
//! `.p7m` and ASiC containers. Checks integrity, the signature value, the certificate chain
//! (at the signing time, against the operating system's trust store) and RFC 3161 time-stamps.
//! Revocation is not checked.

use std::path::Path;

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Local, Utc};

use crate::certs::{self, ChainProblem, HashAlg};
use crate::cms::{self, read_tlv};
use crate::i18n::t;
use crate::x509::{self, Cert};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Clone, Debug)]
pub struct Line {
    pub status: Status,
    pub text: String,
}

fn line(status: Status, text: impl Into<String>) -> Line {
    Line { status, text: text.into() }
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub title: String,
    /// e.g. "PAdES B-LT", "CAdES-T".
    pub level: String,
    /// (label, value) rows.
    pub facts: Vec<(String, String)>,
    pub checks: Vec<Line>,
}

impl Report {
    pub fn status(&self) -> Status {
        self.checks.iter().map(|l| l.status).max().unwrap_or(Status::Ok)
    }
}

fn when(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%d.%m.%Y %H:%M:%S").to_string()
}

// ---------- CMS ----------

fn oid_is(content: &[u8], dotted: &str) -> bool {
    cms::oid(dotted).get(2..) == Some(content)
}

fn hash_alg(oid: &[u8]) -> Option<HashAlg> {
    [("1.3.14.3.2.26", HashAlg::Sha1), ("2.16.840.1.101.3.4.2.1", HashAlg::Sha256), ("2.16.840.1.101.3.4.2.2", HashAlg::Sha384), ("2.16.840.1.101.3.4.2.3", HashAlg::Sha512)]
        .into_iter()
        .find(|(o, _)| oid_is(oid, o))
        .map(|(_, h)| h)
}

/// Hash implied by the signature algorithm, `None` for plain rsaEncryption / ecPublicKey,
/// `Err` for algorithms we cannot check (e.g. RSASSA-PSS).
fn sig_hash(oid: &[u8]) -> Result<Option<HashAlg>, String> {
    let table = [
        ("1.2.840.113549.1.1.5", HashAlg::Sha1),
        ("1.2.840.113549.1.1.11", HashAlg::Sha256),
        ("1.2.840.113549.1.1.12", HashAlg::Sha384),
        ("1.2.840.113549.1.1.13", HashAlg::Sha512),
        ("1.2.840.10045.4.1", HashAlg::Sha1),
        ("1.2.840.10045.4.3.2", HashAlg::Sha256),
        ("1.2.840.10045.4.3.3", HashAlg::Sha384),
        ("1.2.840.10045.4.3.4", HashAlg::Sha512),
    ];
    if let Some((_, h)) = table.iter().find(|(o, _)| oid_is(oid, o)) {
        return Ok(Some(*h));
    }
    if oid_is(oid, "1.2.840.113549.1.1.1") || oid_is(oid, "1.2.840.10045.2.1") {
        return Ok(None);
    }
    Err(dotted(oid))
}

fn dotted(oid: &[u8]) -> String {
    let mut parts = Vec::new();
    if let Some(&first) = oid.first() {
        parts.push((first / 40).to_string());
        parts.push((first % 40).to_string());
    }
    let mut v: u64 = 0;
    for &b in oid.iter().skip(1) {
        v = v << 7 | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            parts.push(v.to_string());
            v = 0;
        }
    }
    parts.join(".")
}

/// OID content of an AlgorithmIdentifier.
fn alg_oid(alg_id: &[u8]) -> &[u8] {
    read_tlv(alg_id).and_then(|(_, a, _)| read_tlv(a)).map(|(_, o, _)| o).unwrap_or_default()
}

struct Signed<'a> {
    econtent: Option<Vec<u8>>,
    certs: Vec<Vec<u8>>,
    sid_issuer_serial: Option<(&'a [u8], &'a [u8])>,
    sid_ski: Option<&'a [u8]>,
    digest_alg: &'a [u8],
    /// Full TLV (implicit `[0]`).
    signed_attrs: Option<&'a [u8]>,
    sig_alg: &'a [u8],
    signature: &'a [u8],
    /// Content of `[1]`.
    unsigned_attrs: Option<&'a [u8]>,
}

/// Parses a DER ContentInfo(SignedData) with its first SignerInfo.
fn parse_signed(ci: &[u8]) -> Option<Signed<'_>> {
    let (_, body, _) = read_tlv(ci).filter(|t| t.0 == 0x30)?;
    let (_, oid, rest) = read_tlv(body).filter(|t| t.0 == 0x06)?;
    if !oid_is(oid, "1.2.840.113549.1.7.2") {
        return None;
    }
    let (_, sd, _) = read_tlv(rest).filter(|t| t.0 == 0xA0)?;
    let (_, sd, _) = read_tlv(sd).filter(|t| t.0 == 0x30)?;
    let (_, _, r) = read_tlv(sd)?; // version
    let (_, _, r) = read_tlv(r)?; // digestAlgorithms
    let (_, eci, mut r) = read_tlv(r).filter(|t| t.0 == 0x30)?;
    let (_, _, eci) = read_tlv(eci)?; // eContentType
    let econtent = match read_tlv(eci) {
        Some((0xA0, e, _)) => match read_tlv(e)? {
            (0x04, v, _) => Some(v.to_vec()),
            (0x24, mut chunks, _) => {
                let mut v = Vec::new();
                while let Some((_, c, more)) = read_tlv(chunks) {
                    v.extend_from_slice(c);
                    chunks = more;
                }
                Some(v)
            }
            _ => None,
        },
        _ => None,
    };
    let mut certs = Vec::new();
    if r.first() == Some(&0xA0) {
        let (_, mut list, rest) = read_tlv(r)?;
        while let Some(c) = cms::tlv_bytes(list) {
            certs.push(c.to_vec());
            list = &list[c.len()..];
        }
        r = rest;
    }
    if r.first() == Some(&0xA1) {
        r = read_tlv(r)?.2;
    }
    let (_, infos, _) = read_tlv(r).filter(|t| t.0 == 0x31)?;
    let (_, si, _) = read_tlv(infos).filter(|t| t.0 == 0x30)?;
    let (_, _, r) = read_tlv(si)?; // version
    let (sid_tag, sid, r) = read_tlv(r)?;
    let (sid_issuer_serial, sid_ski) = match sid_tag {
        0x30 => {
            let issuer = cms::tlv_bytes(sid)?;
            let (_, serial, _) = read_tlv(&sid[issuer.len()..])?;
            (Some((issuer, serial)), None)
        }
        0x80 => (None, Some(sid)),
        _ => return None,
    };
    let digest_alg = cms::tlv_bytes(r)?;
    let mut r = &r[digest_alg.len()..];
    let mut signed_attrs = None;
    if r.first() == Some(&0xA0) {
        let attrs = cms::tlv_bytes(r)?;
        signed_attrs = Some(attrs);
        r = &r[attrs.len()..];
    }
    let sig_alg = cms::tlv_bytes(r)?;
    let (_, signature, r) = read_tlv(&r[sig_alg.len()..]).filter(|t| t.0 == 0x04)?;
    let unsigned_attrs = read_tlv(r).filter(|t| t.0 == 0xA1).map(|(_, u, _)| u);
    Some(Signed { econtent, certs, sid_issuer_serial, sid_ski, digest_alg: alg_oid(digest_alg), signed_attrs, sig_alg: alg_oid(sig_alg), signature, unsigned_attrs })
}

/// First value (full TLV) of attribute `oid` in an attribute list (content of a SET / `[0]` / `[1]`).
fn attr<'a>(mut attrs: &'a [u8], oid: &str) -> Option<&'a [u8]> {
    while let Some((_, a, more)) = read_tlv(attrs) {
        if let Some((_, o, values)) = read_tlv(a)
            && oid_is(o, oid)
        {
            let (_, values, _) = read_tlv(values)?;
            return cms::tlv_bytes(values);
        }
        attrs = more;
    }
    None
}

fn magnitude(int: &[u8]) -> &[u8] {
    &int[int.iter().take_while(|&&b| b == 0).count().min(int.len().saturating_sub(1))..]
}

/// Checked CMS: who signed, integrity of the content and the signature value.
struct CmsCheck {
    signer: Option<Cert>,
    certs: Vec<Vec<u8>>,
    integrity: Line,
    signature: Line,
    signing_time: Option<DateTime<Utc>>,
    tokens: Vec<Vec<u8>>,
    /// The bytes the signature time-stamp covers (CMS: the signature value; XAdES: the
    /// canonical ds:SignatureValue element).
    signature_value: Vec<u8>,
    econtent: Option<Vec<u8>>,
    weak: bool,
}

/// `content`: the detached data; `None` = the encapsulated content.
fn check_cms(ci: &[u8], content: Option<&[u8]>) -> Result<CmsCheck> {
    let v = &t().verify;
    let s = parse_signed(ci).ok_or_else(|| anyhow!("{}", v.err_cms))?;
    let parsed: Vec<Cert> = s.certs.iter().filter_map(|d| x509::parse(d)).collect();
    let signer = parsed
        .iter()
        .find(|c| match (s.sid_issuer_serial, s.sid_ski) {
            (Some((issuer, serial)), _) => c.issuer == issuer && magnitude(&c.serial) == magnitude(serial),
            (_, Some(ski)) => c.ski == ski,
            _ => false,
        })
        .cloned();
    let hash = hash_alg(s.digest_alg);
    let data = content.or(s.econtent.as_deref());
    let attrs = s.signed_attrs.and_then(|a| read_tlv(a)).map(|(_, a, _)| a);
    let mut weak = hash == Some(HashAlg::Sha1);

    let integrity = match (hash, data) {
        (None, _) => line(Status::Fail, v.unsupported_alg.replace("{alg}", &dotted(s.digest_alg))),
        (_, None) => line(Status::Fail, v.content_missing),
        (Some(h), Some(data)) => {
            let digest = h.digest(data);
            let expected = match attrs {
                Some(a) => attr(a, "1.2.840.113549.1.9.4").and_then(read_tlv).map(|(_, d, _)| d.to_vec()),
                None => Some(digest.clone()),
            };
            if expected.as_deref() == Some(&digest[..]) { line(Status::Ok, v.integrity_ok) } else { line(Status::Fail, v.integrity_fail) }
        }
    };

    let signature = match (&signer, hash, sig_hash(s.sig_alg)) {
        (None, _, _) => line(Status::Fail, v.signer_cert_missing),
        (_, _, Err(alg)) => line(Status::Warn, v.unsupported_alg.replace("{alg}", &alg)),
        (_, None, _) => line(Status::Fail, v.unsupported_alg.replace("{alg}", &dotted(s.digest_alg))),
        (Some(cert), Some(h), Ok(sh)) => {
            let sh = sh.unwrap_or(h);
            weak |= sh == HashAlg::Sha1;
            let digest = match s.signed_attrs {
                // The signature covers the attributes DER-encoded as a SET (tag 0x31, not [0]).
                Some(a) => {
                    let mut set = a.to_vec();
                    set[0] = 0x31;
                    sh.digest(&set)
                }
                None => sh.digest(data.unwrap_or_default()),
            };
            match certs::verify_digest(&cert.der, sh, &digest, s.signature) {
                Ok(true) => line(Status::Ok, v.signature_ok.replace("{alg}", sh.name())),
                Ok(false) => line(Status::Fail, v.signature_fail),
                Err(e) => line(Status::Fail, format!("{}: {e:#}", v.signature_fail)),
            }
        }
    };

    let signing_time = attrs.and_then(|a| attr(a, "1.2.840.113549.1.9.5")).and_then(|tv| read_tlv(tv)).and_then(|(tag, t, _)| x509::parse_time(tag, t));
    let tokens = s.unsigned_attrs.map(|u| cms::timestamp_tokens_in(u)).unwrap_or_default();
    Ok(CmsCheck { signer, certs: s.certs.clone(), integrity, signature, signing_time, tokens, signature_value: s.signature.to_vec(), econtent: s.econtent.clone(), weak })
}

// ---------- chain and time-stamps ----------

fn chain_line(cert: &Cert, extra: &[Vec<u8>], at: DateTime<Utc>) -> Line {
    let v = &t().verify;
    match certs::check_chain(&cert.der, extra, at) {
        Err(e) => line(Status::Warn, format!("{}: {e:#}", v.chain_error)),
        Ok(chain) if chain.problems.is_empty() => line(Status::Ok, v.chain_ok.replace("{chain}", &chain.names.join(" → "))),
        Ok(chain) => {
            let root = chain.names.last().cloned().unwrap_or_default();
            let mut status = Status::Warn;
            let texts: Vec<String> = chain
                .problems
                .iter()
                .map(|p| match p {
                    ChainProblem::NotTimeValid => {
                        status = Status::Fail;
                        v.chain_expired.replace("{time}", &when(at))
                    }
                    ChainProblem::Revoked => {
                        status = Status::Fail;
                        v.chain_revoked.to_string()
                    }
                    ChainProblem::BadSignature => {
                        status = Status::Fail;
                        v.chain_bad_signature.to_string()
                    }
                    ChainProblem::UntrustedRoot => v.chain_untrusted.replace("{root}", &root),
                    ChainProblem::PartialChain => v.chain_partial.to_string(),
                    ChainProblem::Other(code) => format!("{}: {code}", v.chain_error),
                })
                .collect();
            line(status, texts.join("; "))
        }
    }
}

struct TokenCheck {
    time: Option<DateTime<Utc>>,
    tsa: String,
    line: Line,
    chain: Line,
    certs: Vec<Vec<u8>>,
}

/// Checks an RFC 3161 token whose message imprint must be the hash of `stamped`.
fn check_token(token: &[u8], stamped: &[u8], extra: &[Vec<u8>]) -> TokenCheck {
    let v = &t().verify;
    let fail = |why: String| TokenCheck { time: None, tsa: String::new(), line: line(Status::Fail, v.timestamp_fail.replace("{why}", &why)), chain: line(Status::Ok, ""), certs: Vec::new() };
    let c = match check_cms(token, None) {
        Ok(c) => c,
        Err(e) => return fail(format!("{e:#}")),
    };
    let tsa = c.signer.as_ref().map(Cert::name).unwrap_or_default();
    // TSTInfo { version, policy, messageImprint { alg, hash }, serial, genTime, ... }
    let tst = (|| {
        let (_, tst, _) = read_tlv(c.econtent.as_deref()?)?;
        let (_, _, r) = read_tlv(tst)?;
        let (_, _, r) = read_tlv(r)?;
        let (_, imprint, r) = read_tlv(r)?;
        let alg = cms::tlv_bytes(imprint)?;
        let (_, hash, _) = read_tlv(&imprint[alg.len()..])?;
        let (_, _, r) = read_tlv(r)?;
        let (tag, gen_time, _) = read_tlv(r)?;
        Some((hash_alg(alg_oid(alg)), hash.to_vec(), x509::parse_time(tag, gen_time)))
    })();
    let Some((imprint_alg, imprint, time)) = tst else { return fail(v.err_cms.into()) };
    let imprint_ok = imprint_alg.is_some_and(|h| h.digest(stamped) == imprint);
    let all: Vec<Vec<u8>> = c.certs.iter().chain(extra).cloned().collect();
    let chain = match (&c.signer, time) {
        (Some(cert), Some(at)) => chain_line(cert, &all, at),
        _ => line(Status::Fail, v.signer_cert_missing),
    };
    let line = if c.integrity.status == Status::Fail || c.signature.status == Status::Fail {
        line(Status::Fail, v.timestamp_fail.replace("{why}", &format!("{}; {}", c.integrity.text, c.signature.text)))
    } else if !imprint_ok {
        line(Status::Fail, v.timestamp_fail.replace("{why}", v.imprint_mismatch))
    } else {
        line(Status::Ok, v.timestamp_ok.replace("{tsa}", &tsa).replace("{time}", &time.map(when).unwrap_or_default()))
    };
    TokenCheck { time, tsa, line, chain, certs: c.certs }
}

/// Facts, signature checks and the signature time-stamp of one CMS signature.
fn signature_report(title: String, c: &CmsCheck, claimed: Option<DateTime<Utc>>, extra: &[Vec<u8>], r: &mut Report) -> Option<TokenCheck> {
    let v = &t().verify;
    r.title = title;
    if let Some(cert) = &c.signer {
        r.facts.push((v.signer.into(), cert.name()));
        r.facts.push((v.issuer.into(), cert.issuer_name()));
        if let (Some(a), Some(b)) = (cert.not_before, cert.not_after) {
            r.facts.push((v.cert_validity.into(), format!("{} - {}", a.with_timezone(&Local).format("%d.%m.%Y"), b.with_timezone(&Local).format("%d.%m.%Y"))));
        }
    }
    let claimed = c.signing_time.or(claimed);
    if let Some(t) = claimed {
        r.facts.push((v.claimed_time.into(), when(t)));
    }
    r.checks.push(c.integrity.clone());
    r.checks.push(c.signature.clone());
    if c.weak {
        r.checks.push(line(Status::Warn, v.weak_sha1));
    }
    let token = c.tokens.first().map(|tok| check_token(tok, &c.signature_value, extra));
    match &token {
        Some(tc) => {
            r.checks.push(tc.line.clone());
            if tc.chain.status != Status::Ok {
                r.checks.push(line(tc.chain.status, format!("{} ({}): {}", v.tsa, tc.tsa, tc.chain.text)));
            }
        }
        None => r.checks.push(line(Status::Warn, v.no_timestamp)),
    }
    let at = token.as_ref().filter(|tc| tc.line.status == Status::Ok).and_then(|tc| tc.time).or(claimed).unwrap_or_else(Utc::now);
    if let Some(cert) = &c.signer {
        let all: Vec<Vec<u8>> = c.certs.iter().chain(extra).chain(token.iter().flat_map(|tc| tc.certs.iter())).cloned().collect();
        r.checks.push(chain_line(cert, &all, at));
    }
    token
}

// ---------- formats ----------

pub fn verify_pdf(bytes: &[u8], password: Option<&str>) -> Result<Vec<Report>> {
    let v = &t().verify;
    let found = crate::pdf::signatures(bytes, password)?;
    if found.sigs.is_empty() {
        bail!("{}", v.no_signatures);
    }
    let mut reports = Vec::new();
    for (i, s) in found.sigs.iter().enumerate() {
        let mut r = Report::default();
        let title = if s.field.is_empty() { format!("#{}", i + 1) } else { s.field.clone() };
        let (a, b, c) = match s.byte_range[..] {
            [0, a, b, c] if a >= 0 && b > a && c >= 0 && (b + c) as usize <= bytes.len() => (a as usize, b as usize, c as usize),
            _ => {
                r.title = title;
                r.checks.push(line(Status::Fail, v.byte_range_invalid));
                reports.push(r);
                continue;
            }
        };
        // The gap must be exactly the hex string of /Contents.
        if bytes[a] != b'<' || bytes[b - 1] != b'>' {
            r.title = title;
            r.checks.push(line(Status::Fail, v.byte_range_invalid));
            reports.push(r);
            continue;
        }
        let covered: Vec<u8> = [&bytes[..a], &bytes[b..b + c]].concat();
        let later_ts = found.sigs[i + 1..].iter().any(|x| x.doc_timestamp);
        if s.doc_timestamp {
            r.title = format!("{} ({})", title, v.kind_doc_timestamp);
            let tc = check_token(&s.contents, &covered, &found.dss_certs);
            if !tc.tsa.is_empty() {
                r.facts.push((v.tsa.into(), tc.tsa.clone()));
            }
            r.checks.push(tc.line.clone());
            r.checks.push(tc.chain.clone());
            r.level = "PAdES document timestamp".into();
        } else {
            let check = match s.sub_filter.as_str() {
                "adbe.pkcs7.sha1" => check_cms(&s.contents, None).map(|mut c| {
                    if c.econtent.as_deref() != Some(&HashAlg::Sha1.digest(&covered)[..]) {
                        c.integrity = line(Status::Fail, v.integrity_fail);
                    }
                    c
                }),
                "ETSI.CAdES.detached" | "adbe.pkcs7.detached" => check_cms(&s.contents, Some(&covered)),
                other => {
                    r.title = title;
                    r.checks.push(line(Status::Warn, v.unsupported_alg.replace("{alg}", other)));
                    reports.push(r);
                    continue;
                }
            };
            let c = match check {
                Ok(c) => c,
                Err(e) => {
                    r.title = title;
                    r.checks.push(line(Status::Fail, format!("{e:#}")));
                    reports.push(r);
                    continue;
                }
            };
            if !s.reason.is_empty() {
                r.facts.push((v.reason.into(), s.reason.clone()));
            }
            if !s.location.is_empty() {
                r.facts.push((v.location.into(), s.location.clone()));
            }
            let token = signature_report(title, &c, s.time, &found.dss_certs, &mut r);
            let ts_ok = token.as_ref().is_some_and(|tc| tc.line.status == Status::Ok);
            r.level = match (s.sub_filter == "ETSI.CAdES.detached", ts_ok, found.has_dss, later_ts) {
                (false, _, _, _) => format!("PKCS#7 ({})", s.sub_filter),
                (true, false, _, _) => "PAdES B-B".into(),
                (true, true, false, _) => "PAdES B-T".into(),
                (true, true, true, false) => "PAdES B-LT".into(),
                (true, true, true, true) => "PAdES B-LTA".into(),
            };
        }
        r.checks.push(coverage(bytes, a, b + c, password));
        reports.push(r);
    }
    Ok(reports)
}

fn coverage(bytes: &[u8], _gap: usize, end: usize, password: Option<&str>) -> Line {
    let v = &t().verify;
    if end == bytes.len() {
        return line(Status::Ok, v.covers_all);
    }
    match crate::pdf::changes_after(bytes, end, password) {
        Err(e) => line(Status::Warn, format!("{}: {e:#}", v.changed_after.replace("{what}", "?"))),
        Ok(ch) if ch.other.is_empty() => {
            let mut what = Vec::new();
            if ch.signatures > 0 {
                what.push(v.later_signatures.replace("{n}", &ch.signatures.to_string()));
            }
            if ch.timestamps > 0 {
                what.push(v.later_timestamps.replace("{n}", &ch.timestamps.to_string()));
            }
            if ch.validation_data {
                what.push(v.later_validation_data.to_string());
            }
            line(Status::Ok, v.later_only.replace("{what}", &what.join(", ")))
        }
        Ok(ch) => {
            let mut list = ch.other.clone();
            if list.len() > 5 {
                let n = list.len() - 5;
                list.truncate(5);
                list.push(format!("+{n}"));
            }
            line(Status::Warn, v.changed_after.replace("{what}", &list.join(", ")))
        }
    }
}

fn cades_report(name: String, c: &CmsCheck) -> Report {
    let mut r = Report::default();
    let token = signature_report(name, c, None, &[], &mut r);
    r.level = if token.is_some_and(|tc| tc.line.status == Status::Ok) { "CAdES-T".into() } else { "CAdES-B".into() };
    r
}

/// `.p7s` (the original is the same path without `.p7s`) or `.p7m`.
pub fn verify_cades(path: &Path) -> Result<Vec<Report>> {
    let v = &t().verify;
    let der = std::fs::read(path)?;
    let der = der_or_pem(&der);
    let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let detached = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("p7s"));
    let c = if detached {
        let original = path.with_extension("");
        let data = std::fs::read(&original).map_err(|_| anyhow!("{}", v.original_missing.replace("{name}", &original.display().to_string())))?;
        check_cms(&der, Some(&data))?
    } else {
        check_cms(&der, None)?
    };
    Ok(vec![cades_report(name, &c)])
}

/// Base64 / PEM wrapped signatures (some tools write `.p7s` that way).
fn der_or_pem(b: &[u8]) -> Vec<u8> {
    use base64::Engine;
    if b.first() == Some(&0x30) {
        return b.to_vec();
    }
    let text: String = String::from_utf8_lossy(b).lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(text.trim()).unwrap_or_else(|_| b.to_vec())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// `(URI, digest algorithm URI, base64 digest)` of every DataObjectReference, and the SigReference URI.
fn manifest_refs(xml: &str) -> (Option<String>, Vec<(String, String, String)>) {
    let attr_of = |tag: &str, name: &str| -> Option<String> {
        let start = tag.find(&format!("{name}=\""))? + name.len() + 2;
        Some(xml_unescape(&tag[start..start + tag[start..].find('"')?]))
    };
    let sig_ref = xml.split("SigReference").nth(1).and_then(|tag| attr_of(&tag[..tag.find('>').unwrap_or(tag.len())], "URI"));
    let mut refs = Vec::new();
    for part in xml.split("DataObjectReference").skip(1) {
        let Some(head_end) = part.find('>') else { continue };
        let Some(uri) = attr_of(&part[..head_end], "URI") else { continue };
        let alg = part.split("DigestMethod").nth(1).and_then(|m| attr_of(&m[..m.find('>').unwrap_or(m.len())], "Algorithm")).unwrap_or_default();
        let value = part.split("DigestValue>").nth(1).map(|v| v.trim_end_matches("</").split('<').next().unwrap_or_default().trim().to_string()).unwrap_or_default();
        refs.push((uri, alg, value));
    }
    (sig_ref, refs)
}

fn xml_digest(alg: &str) -> Option<HashAlg> {
    match alg.rsplit('#').next()? {
        "sha1" => Some(HashAlg::Sha1),
        "sha256" => Some(HashAlg::Sha256),
        "sha384" => Some(HashAlg::Sha384),
        "sha512" => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// ASiC-E (manifest + CAdES) and ASiC-S (one file + CAdES) containers.
pub fn verify_asic(bytes: &[u8]) -> Result<Vec<Report>> {
    use base64::Engine;
    let v = &t().verify;
    let entries = crate::asic::read_zip(bytes)?;
    let get = |name: &str| entries.iter().find(|(n, _)| n == name).map(|(_, d)| d.as_slice());
    let data_files: Vec<&(String, Vec<u8>)> = entries.iter().filter(|(n, _)| n != "mimetype" && !n.starts_with("META-INF/") && !n.ends_with('/')).collect();
    let sig_names: Vec<&String> = entries.iter().map(|(n, _)| n).filter(|n| n.starts_with("META-INF/") && n.to_ascii_lowercase().contains("signature") && n.ends_with(".p7s")).collect();
    if sig_names.is_empty() {
        let xades: Vec<&(String, Vec<u8>)> = entries.iter().filter(|(n, _)| n.starts_with("META-INF/") && n.contains("signatures") && n.ends_with(".xml")).collect();
        if xades.is_empty() {
            bail!("{}", v.no_signatures);
        }
        let resolve = |uri: &str| get(&percent_decode(uri)).map(<[u8]>::to_vec);
        let mut reports = Vec::new();
        for (name, xml) in xades {
            for mut r in verify_xades(xml, &resolve)? {
                r.level = format!("ASiC-E {}", r.level);
                r.title = format!("{} ({})", r.title, name.trim_start_matches("META-INF/"));
                let uncovered: Vec<String> = data_files.iter().map(|(n, _)| n.clone()).filter(|n| !r.facts.iter().any(|(_, f)| f.split(", ").any(|x| x == n))).collect();
                if !uncovered.is_empty() {
                    r.checks.push(line(Status::Warn, v.files_not_covered.replace("{files}", &uncovered.join(", "))));
                }
                reports.push(r);
            }
        }
        return Ok(reports);
    }
    let manifests: Vec<(&String, String)> = entries
        .iter()
        .filter(|(n, _)| n.starts_with("META-INF/ASiCManifest") && n.ends_with(".xml"))
        .map(|(n, d)| (n, String::from_utf8_lossy(d).into_owned()))
        .collect();
    let mut reports = Vec::new();
    for sig_name in sig_names {
        let der = der_or_pem(get(sig_name).unwrap_or_default());
        let short = sig_name.trim_start_matches("META-INF/").to_string();
        let manifest = manifests.iter().find(|(_, xml)| manifest_refs(xml).0.as_deref() == Some(sig_name.as_str()));
        let (signed, r) = match manifest {
            Some((mname, xml)) => (get(mname).unwrap_or_default(), Some(manifest_refs(xml).1)),
            None if data_files.len() == 1 => (data_files[0].1.as_slice(), None),
            None => {
                reports.push(Report { title: short, checks: vec![line(Status::Fail, v.manifest_missing)], ..Default::default() });
                continue;
            }
        };
        let c = check_cms(&der, Some(signed))?;
        let mut report = cades_report(short, &c);
        report.level = format!("ASiC-{} {}", if r.is_some() { "E" } else { "S" }, report.level);
        match r {
            Some(refs) => {
                let mut bad = Vec::new();
                for (uri, alg, value) in &refs {
                    let name = percent_decode(uri);
                    let ok = match (get(&name), xml_digest(alg), base64::engine::general_purpose::STANDARD.decode(value)) {
                        (Some(data), Some(h), Ok(expected)) => h.digest(data) == expected,
                        _ => false,
                    };
                    if !ok {
                        bad.push(name);
                    }
                }
                let uncovered: Vec<String> = data_files.iter().map(|(n, _)| n.clone()).filter(|n| !refs.iter().any(|(u, _, _)| percent_decode(u) == *n)).collect();
                report.checks.insert(0, if bad.is_empty() { line(Status::Ok, v.files_ok.replace("{n}", &refs.len().to_string())) } else { line(Status::Fail, v.files_changed.replace("{files}", &bad.join(", "))) });
                if !uncovered.is_empty() {
                    report.checks.push(line(Status::Warn, v.files_not_covered.replace("{files}", &uncovered.join(", "))));
                }
                report.facts.push((v.files.into(), refs.iter().map(|(u, _, _)| percent_decode(u)).collect::<Vec<_>>().join(", ")));
            }
            None => report.facts.push((v.files.into(), data_files[0].0.clone())),
        }
        reports.push(report);
    }
    Ok(reports)
}

/// Whether the file type can be verified (PDFs are checked separately for signatures).
/// XML file that contains an XML signature (reads at most the first 64 MB).
pub fn is_signed_xml(path: &Path) -> bool {
    crate::xades::is_xml(path)
        && std::fs::metadata(path).is_ok_and(|m| m.len() < 64 << 20)
        && std::fs::read(path).is_ok_and(|b| b.windows(crate::xades::NS_DS.len()).any(|w| w == crate::xades::NS_DS.as_bytes()))
}

pub fn is_signature_file(path: &Path) -> bool {
    path.extension().map(|e| e.to_ascii_lowercase()).is_some_and(|e| ["p7s", "p7m", "asice", "sce", "asics", "scs"].iter().any(|x| e == *x))
}

pub fn verify_file(path: &Path, password: Option<&str>) -> Result<Vec<Report>> {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "xml" => {
            let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            // Detached references: only files in the same folder.
            let resolve = |uri: &str| {
                let name = percent_decode(uri);
                let file = Path::new(&name).file_name()?;
                std::fs::read(dir.join(file)).ok()
            };
            verify_xades(&std::fs::read(path)?, &resolve)
        }
        "pdf" => verify_pdf(&std::fs::read(path)?, password),
        "p7s" | "p7m" => verify_cades(path),
        "asice" | "sce" | "asics" | "scs" => verify_asic(&std::fs::read(path)?),
        _ => bail!("{}", t().verify.no_signatures),
    }
}

// ---------- XAdES / XML-DSig ----------

fn xml_hash(uri: &str) -> Option<HashAlg> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1" => Some(HashAlg::Sha1),
        "http://www.w3.org/2001/04/xmlenc#sha256" => Some(HashAlg::Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some(HashAlg::Sha384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// (hash, ECDSA?) of an XML-DSig SignatureMethod.
fn xml_sig_alg(uri: &str) -> Option<(HashAlg, bool)> {
    let (alg, hash) = uri.rsplit_once('#')?;
    let ecdsa = match hash.split('-').next()? {
        "rsa" => false,
        "ecdsa" => true,
        _ => return None,
    };
    let h = match hash.rsplit('-').next()? {
        "sha1" => HashAlg::Sha1,
        "sha256" => HashAlg::Sha256,
        "sha384" => HashAlg::Sha384,
        "sha512" => HashAlg::Sha512,
        _ => return None,
    };
    let _ = alg;
    Some((h, ecdsa))
}

fn b64_text(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(clean).ok()
}

/// Canonicalization settings of a `CanonicalizationMethod` / `Transform` element.
fn c14n_of(doc: &crate::xml::Doc, el: usize) -> Option<crate::xml::C14n> {
    let mut c = crate::xml::C14n::from_uri(doc.attr(el, "Algorithm")?)?;
    if let Some(inc) = doc.child(el, crate::xml::EXC_C14N, "InclusiveNamespaces") {
        c.inclusive_prefixes = doc.attr(inc, "PrefixList").unwrap_or_default().split_whitespace().map(str::to_string).collect();
    }
    Some(c)
}

/// Verifies every `ds:Signature` in an XML document. `resolve` returns the content of
/// external references (detached signatures, ASiC containers).
pub fn verify_xades(bytes: &[u8], resolve: &dyn Fn(&str) -> Option<Vec<u8>>) -> Result<Vec<Report>> {
    use crate::xades::{ENVELOPED, NS_DS, SIGNED_PROPERTIES};
    use crate::xml;
    let v = &t().verify;
    let doc = xml::parse(bytes)?;
    let sigs: Vec<usize> = doc.descendants(0).into_iter().filter(|&n| doc.is(n, NS_DS, "Signature")).collect();
    if sigs.is_empty() {
        bail!("{}", v.no_signatures);
    }
    let ns_xades = [crate::xades::NS_XADES, "http://uri.etsi.org/01903/v1.4.1#", "http://uri.etsi.org/01903/v1.1.1#"];
    let find = |under: usize, local: &str| doc.descendants(under).into_iter().find(|&n| doc.name(n).is_some_and(|(ns, l)| l == local && (ns_xades.contains(&ns.as_str()) || ns == NS_DS)));
    let mut reports = Vec::new();
    for (i, &s) in sigs.iter().enumerate() {
        let title = format!("XAdES #{}", i + 1);
        let mut problems: Vec<String> = Vec::new();
        let mut unsupported: Vec<String> = Vec::new();
        let si = doc.child(s, NS_DS, "SignedInfo").ok_or_else(|| anyhow!("{}: SignedInfo", v.err_cms))?;
        let si_c14n = doc.child(si, NS_DS, "CanonicalizationMethod").and_then(|c| c14n_of(&doc, c));
        // References.
        let mut referenced = Vec::new();
        let mut has_props_ref = false;
        for r in doc.elements(si).filter(|&r| doc.is(r, NS_DS, "Reference")) {
            let uri = doc.attr(r, "URI").unwrap_or_default().to_string();
            if doc.attr(r, "Type") == Some(SIGNED_PROPERTIES) {
                has_props_ref = true;
            }
            let mut exclude = None;
            let mut c14n: Option<xml::C14n> = None;
            if let Some(tr) = doc.child(r, NS_DS, "Transforms") {
                for tf in doc.elements(tr) {
                    let alg = doc.attr(tf, "Algorithm").unwrap_or_default();
                    if alg == ENVELOPED {
                        exclude = Some(s);
                    } else if let Some(c) = c14n_of(&doc, tf) {
                        c14n = Some(c);
                    } else {
                        unsupported.push(alg.to_string());
                    }
                }
            }
            let digest_alg = doc.child(r, NS_DS, "DigestMethod").and_then(|d| doc.attr(d, "Algorithm")).unwrap_or_default();
            let expected = doc.child(r, NS_DS, "DigestValue").map(|d| doc.text(d)).and_then(|t| b64_text(&t));
            let Some(h) = xml_hash(digest_alg) else {
                unsupported.push(digest_alg.to_string());
                continue;
            };
            let data = if uri.is_empty() || uri.starts_with('#') {
                let node = if uri.is_empty() { Some(0) } else { doc.by_id(&uri[1..]) };
                // Same-document references never include comments. Without a C14N transform the
                // specification uses inclusive C14N 1.0; some signers (e.g. signxml) use the
                // SignedInfo method instead, so that is accepted too.
                let opts = xml::C14n { comments: false, ..c14n.clone().unwrap_or_default() };
                let mut out = node.map(|n| xml::canonicalize(&doc, n, &opts, exclude));
                if c14n.is_none()
                    && let (Some(n), Some(alt)) = (node, si_c14n.clone())
                    && out.as_ref().map(|d| h.digest(d)) != expected
                {
                    out = Some(xml::canonicalize(&doc, n, &xml::C14n { comments: false, ..alt }, exclude));
                }
                out
            } else {
                referenced.push(percent_decode(&uri));
                resolve(&uri).and_then(|raw| match &c14n {
                    Some(opts) => xml::parse(&raw).ok().map(|d| xml::canonicalize(&d, 0, opts, None)),
                    None => Some(raw),
                })
            };
            let ok = data.as_ref().is_some_and(|d| Some(h.digest(d)) == expected);
            if !ok {
                let label = if uri.is_empty() { v.whole_document.to_string() } else { percent_decode(&uri) };
                problems.push(if data.is_none() { v.reference_missing.replace("{uri}", &label) } else { label });
            }
        }
        let integrity = if !problems.is_empty() {
            line(Status::Fail, format!("{} ({})", v.integrity_fail, problems.join(", ")))
        } else if !unsupported.is_empty() {
            line(Status::Warn, v.unsupported_alg.replace("{alg}", &unsupported.join(", ")))
        } else {
            line(Status::Ok, v.integrity_ok)
        };

        // Certificates: KeyInfo and (XAdES-LT) CertificateValues.
        let mut certs: Vec<Vec<u8>> = doc.descendants(s).into_iter().filter(|&n| doc.name(n).is_some_and(|(_, l)| l == "X509Certificate" || l == "EncapsulatedX509Certificate")).filter_map(|n| b64_text(&doc.text(n))).collect();
        certs.dedup();
        let parsed: Vec<Cert> = certs.iter().filter_map(|d| x509::parse(d)).collect();
        // SigningCertificate(V2): the signer is the certificate whose digest is referenced.
        let cert_refs: Vec<(HashAlg, Vec<u8>)> = find(s, "SigningCertificateV2")
            .or_else(|| find(s, "SigningCertificate"))
            .map(|sc| {
                doc.descendants(sc)
                    .into_iter()
                    .filter(|&n| doc.name(n).is_some_and(|(_, l)| l == "CertDigest"))
                    .filter_map(|cd| {
                        let h = xml_hash(doc.child(cd, NS_DS, "DigestMethod").and_then(|m| doc.attr(m, "Algorithm"))?)?;
                        Some((h, b64_text(&doc.text(doc.child(cd, NS_DS, "DigestValue")?))?))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let signer = if cert_refs.is_empty() {
            parsed.first().cloned()
        } else {
            parsed.iter().find(|c| cert_refs.iter().any(|(h, d)| h.digest(&c.der) == *d)).cloned()
        };

        let sig_method = doc.child(si, NS_DS, "SignatureMethod").and_then(|m| doc.attr(m, "Algorithm")).unwrap_or_default();
        let value_el = doc.child(s, NS_DS, "SignatureValue");
        let value = value_el.and_then(|e| b64_text(&doc.text(e))).unwrap_or_default();
        let mut weak = false;
        let signature = match (&signer, xml_sig_alg(sig_method), &si_c14n) {
            (None, _, _) if !cert_refs.is_empty() => line(Status::Fail, v.signing_cert_mismatch),
            (None, _, _) => line(Status::Fail, v.signer_cert_missing),
            (_, None, _) => line(Status::Warn, v.unsupported_alg.replace("{alg}", sig_method)),
            (_, _, None) => line(Status::Warn, v.unsupported_alg.replace("{alg}", "CanonicalizationMethod")),
            (Some(cert), Some((h, ecdsa)), Some(opts)) => {
                weak = h == HashAlg::Sha1;
                let digest = h.digest(&xml::canonicalize(&doc, si, opts, None));
                let sig = if ecdsa { cms::ecdsa_raw_to_der(&value) } else { value.clone() };
                match certs::verify_digest(&cert.der, h, &digest, &sig) {
                    Ok(true) => line(Status::Ok, v.signature_ok.replace("{alg}", h.name())),
                    _ => line(Status::Fail, v.signature_fail),
                }
            }
        };

        // Signature time-stamps cover the canonical ds:SignatureValue element.
        let mut tokens = Vec::new();
        let mut stamped = Vec::new();
        if let (Some(ts), Some(ve)) = (find(s, "SignatureTimeStamp"), value_el) {
            let opts = doc.elements(ts).find(|&c| doc.is(c, NS_DS, "CanonicalizationMethod")).and_then(|c| c14n_of(&doc, c)).unwrap_or_default();
            stamped = xml::canonicalize(&doc, ve, &opts, None);
            if let Some(enc) = doc.elements(ts).find(|&c| doc.name(c).is_some_and(|(_, l)| l == "EncapsulatedTimeStamp")) {
                tokens.extend(b64_text(&doc.text(enc)));
            }
        }
        let signing_time = find(s, "SigningTime").and_then(|n| DateTime::parse_from_rfc3339(doc.text(n).trim()).ok()).map(|t| t.with_timezone(&Utc));
        let check = CmsCheck { signer, certs: certs.clone(), integrity, signature, signing_time, tokens, signature_value: stamped, econtent: None, weak };
        let mut r = Report::default();
        let token = signature_report(title, &check, None, &[], &mut r);
        if !referenced.is_empty() {
            r.facts.push((v.files.into(), referenced.join(", ")));
        }
        let ts_ok = token.is_some_and(|tc| tc.line.status == Status::Ok);
        let base = if has_props_ref { "XAdES" } else { "XML-DSig" };
        r.level = match (ts_ok, find(s, "CertificateValues").is_some() || find(s, "RevocationValues").is_some(), find(s, "ArchiveTimeStamp").is_some()) {
            (_, _, true) => format!("{base}-B-LTA"),
            (true, true, _) => format!("{base}-B-LT"),
            (true, false, _) => format!("{base}-B-T"),
            _ => format!("{base}-B-B"),
        };
        if !has_props_ref {
            r.level = base.into();
        }
        reports.push(r);
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn third_party_pdf_signature_is_intact() {
        let bytes = include_bytes!("../tests/fixtures/signed-by-pyhanko.pdf");
        let reports = verify_pdf(bytes, None).unwrap();
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert!(r.facts.iter().any(|(_, v)| v.contains("Fixture Signer")), "{:?}", r.facts);
        assert_eq!(r.checks[0].status, Status::Ok, "integrity: {:?}", r.checks);
        assert_eq!(r.checks[1].status, Status::Ok, "signature value: {:?}", r.checks);
        assert_eq!(r.checks.last().unwrap().status, Status::Ok, "covers the file: {:?}", r.checks);
    }

    #[test]
    fn detects_tampering_and_appended_changes() {
        let bytes = include_bytes!("../tests/fixtures/signed-by-pyhanko.pdf").to_vec();
        // Change one byte inside the signed range (the version in the header).
        let mut tampered = bytes.clone();
        tampered[7] = b'5';
        let r = &verify_pdf(&tampered, None).unwrap()[0];
        assert_eq!(r.checks[0].status, Status::Fail, "{:?}", r.checks);
        assert_eq!(r.status(), Status::Fail);

        // An incremental update that changes the page after signing.
        let doc = lopdf::Document::load_mem(&bytes).unwrap();
        let page = *doc.get_pages().values().next().unwrap();
        let mut dict = doc.get_dictionary(page).unwrap().clone();
        dict.set("Rotate", 90i64);
        let mut changed = bytes.clone();
        let prev = crate::pdf::tests_support::startxref(&bytes);
        let off = changed.len();
        changed.extend(format!("{} {} obj\n", page.0, page.1).as_bytes());
        changed.extend(crate::pdf::tests_support::obj_bytes(&lopdf::Object::Dictionary(dict)));
        changed.extend(b"\nendobj\n");
        let xref = changed.len();
        let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
        changed.extend(format!("xref\n{} 1\n{off:010} {:05} n\r\ntrailer\n<</Size {} /Root {} {} R /Prev {prev}>>\nstartxref\n{xref}\n%%EOF\n", page.0, page.1, doc.max_id + 1, root.0, root.1).as_bytes());
        let r = &verify_pdf(&changed, None).unwrap()[0];
        assert_eq!(r.checks[0].status, Status::Ok, "the signed revision is intact");
        let cov = r.checks.last().unwrap();
        assert_eq!(cov.status, Status::Warn, "{cov:?}");
        assert!(cov.text.contains("Page"), "{cov:?}");
    }

    #[test]
    fn our_own_second_signature_is_an_allowed_change() {
        let signer = crate::cms::SignerCert { der: vec![0x30, 0], issuer_der: vec![0x30, 0], serial_be: vec![1], chain: vec![vec![0x30, 0]], alg: crate::cms::KeyAlg::Rsa };
        let req = crate::pdf::SignRequest { signer_name: "x".into(), reason: String::new(), location: String::new(), contact: String::new(), time: Local::now(), visible: None, password: None };
        let bytes = include_bytes!("../tests/fixtures/signed-by-pyhanko.pdf");
        let twice = crate::pdf::sign_pdf(bytes, &req, &signer, &|_| Ok(vec![0u8; 256]), None).unwrap();
        let reports = verify_pdf(&twice, None).unwrap();
        assert_eq!(reports.len(), 2);
        let first = reports[0].checks.last().unwrap();
        assert_eq!(first.status, Status::Ok, "only a later signature was added: {first:?}");
    }

    #[test]
    fn manifest_parsing() {
        let xml = r#"<asic:ASiCManifest><asic:SigReference URI="META-INF/signature001.p7s" MimeType="x"/>
  <asic:DataObjectReference URI="a%20b.txt" MimeType="text/plain"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></asic:DataObjectReference></asic:ASiCManifest>"#;
        let (sig, refs) = manifest_refs(xml);
        assert_eq!(sig.as_deref(), Some("META-INF/signature001.p7s"));
        assert_eq!(refs, [("a%20b.txt".to_string(), "http://www.w3.org/2001/04/xmlenc#sha256".to_string(), "AAAA".to_string())]);
        assert_eq!(percent_decode("a%20b%D0%B1.txt"), "a bб.txt");
    }

    #[test]
    fn verifies_xades_from_signxml() {
        for name in ["signxml-rsa-c14n11.xml", "signxml-ecdsa-exc.xml"] {
            let bytes = std::fs::read(format!("{}/tests/fixtures/xades/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
            let reports = verify_xades(&bytes, &|_| None).unwrap();
            assert_eq!(reports.len(), 1, "{name}");
            let r = &reports[0];
            assert_eq!(r.checks[0].status, Status::Ok, "{name}: references {:?}", r.checks);
            assert_eq!(r.checks[1].status, Status::Ok, "{name}: signature value {:?}", r.checks);
            assert!(r.level.starts_with("XAdES"), "{name}: {}", r.level);
            assert!(r.facts.iter().any(|(_, v)| v.contains("signxml fixture")), "{name}: {:?}", r.facts);

            let tampered = String::from_utf8(bytes).unwrap().replacen(">42<", ">43<", 1);
            let r = &verify_xades(tampered.as_bytes(), &|_| None).unwrap()[0];
            assert_eq!(r.checks[0].status, Status::Fail, "{name}: tampering detected {:?}", r.checks);
            assert_eq!(r.status(), Status::Fail);
        }
    }

    #[test]
    fn oid_to_text() {
        assert_eq!(dotted(&cms::oid("1.2.840.113549.1.1.10")[2..]), "1.2.840.113549.1.1.10");
    }

    /// With the real certificate (Windows store / Linux folder): sign a file as .p7s, .p7m and
    /// .asice and verify all three. Uses DOC_SIGNER_TEST_PDF / DOC_SIGNER_THUMB like the other tests.
    #[test]
    #[ignore]
    fn verifies_what_we_sign() {
        let (Ok(input), Ok(thumb_hex)) = (std::env::var("DOC_SIGNER_TEST_PDF"), std::env::var("DOC_SIGNER_THUMB")) else {
            eprintln!("SKIPPED verifies_what_we_sign: set DOC_SIGNER_TEST_PDF and DOC_SIGNER_THUMB");
            return;
        };
        let thumb: Vec<u8> = (0..thumb_hex.len()).step_by(2).map(|i| u8::from_str_radix(&thumb_hex[i..i + 2], 16).unwrap()).collect();
        let signer = crate::certs::load_signer(&thumb).unwrap();
        let sign = |d: &[u8]| crate::certs::sign_data(&thumb, d, signer.alg);
        let data = std::fs::read(&input).unwrap();
        let dir = std::env::temp_dir().join(format!("doc-signer-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("data.bin");
        std::fs::write(&file, &data).unwrap();
        for format in [crate::cades::Format::Detached, crate::cades::Format::Enveloping] {
            let out = dir.join(format!("data.bin.{}", format.extension()));
            std::fs::write(&out, crate::cades::sign(&data, format, &signer, &sign, None).unwrap()).unwrap();
            let r = &verify_file(&out, None).unwrap()[0];
            eprintln!("{:?}", r);
            assert!(r.checks[0].status == Status::Ok && r.checks[1].status == Status::Ok, "{:?}", r.checks);
        }
        let asice = crate::asic::build(&[("data.bin".into(), data.clone())], &signer, &sign, None).unwrap();
        let r = &verify_asic(&asice).unwrap()[0];
        assert!(r.checks[..3].iter().all(|l| l.status == Status::Ok), "{:?}", r.checks);
        // A changed original fails.
        std::fs::write(&file, b"changed").unwrap();
        assert_eq!(verify_file(&dir.join("data.bin.p7s"), None).unwrap()[0].checks[0].status, Status::Fail);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
