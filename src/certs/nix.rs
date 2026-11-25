use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{Local, TimeZone};
use openssl::asn1::Asn1TimeRef;
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::hash::MessageDigest;
use openssl::pkey::{KeyType, PKey, Private};
use openssl::sign::Signer;
use openssl::pkcs12::Pkcs12;
use openssl::x509::{X509, X509NameRef};

use crate::cms::{KeyAlg, SignerCert};
use crate::i18n::t;

/// Content bytes of the Microsoft Document Signing EKU OID (1.3.6.1.4.1.311.10.3.12) as they
/// appear in the certificate DER.
const DOC_SIGNING_OID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x0C];

const FILE_EXTS: [&str; 6] = ["p12", "pfx", "pem", "crt", "cer", "der"];

/// Folder with the certificate files.
pub fn certs_dir() -> PathBuf {
    if let Ok(d) = std::env::var("DOC_SIGNER_CERTS_DIR") {
        return PathBuf::from(d);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("DocSigner").join("certs")
}

/// Key passphrase: DOC_SIGNER_PASS env var, or the first line of a `.pass` file
/// next to the key / PKCS#12 file, or empty.
fn passphrase_for(path: &Path) -> String {
    if let Ok(p) = std::env::var("DOC_SIGNER_PASS") {
        if !p.is_empty() {
            return p;
        }
    }
    let mut pf = path.to_path_buf();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let _ = pf.set_file_name(format!("{name}.pass"));
    std::fs::read_to_string(&pf)
        .ok()
        .and_then(|s| s.lines().next().map(str::to_string))
        .unwrap_or_default()
}

fn is_cert_file(path: &Path) -> bool {
    path.extension().is_some_and(|e| FILE_EXTS.contains(&e.to_string_lossy().to_ascii_lowercase().as_str()))
}

/// One certificate: the leaf, optional extra chain certificates and the private key.
struct Entry {
    cert: X509,
    chain: Vec<X509>,
    key: Option<PKey<Private>>,
}

impl Entry {
    /// SHA-1 of the certificate DER, like the Windows thumbprint.
    fn thumbprint(&self) -> Vec<u8> {
        let der = self.cert.to_der().unwrap_or_default();
        openssl::sha::sha1(&der).to_vec()
    }

    fn info(&self) -> crate::CertInfo {
        crate::CertInfo {
            subject: display_name(self.cert.subject_name()),
            issuer: display_name(self.cert.issuer_name()),
            not_before: local_time(self.cert.not_before()),
            not_after: local_time(self.cert.not_after()),
            thumbprint: self.thumbprint(),
            doc_signing: has_doc_signing_eku(&self.cert),
        }
    }

    fn signer(&self) -> Result<SignerCert> {
        let der = self.cert.to_der()?;
        let issuer_der = self.cert.issuer_name().to_der()?;
        let serial_be = self.cert.serial_number().to_bn()?.to_vec();
        let pub_key = self.cert.public_key()?;
        let alg = if pub_key.is_a(KeyType::RSA) {
            KeyAlg::Rsa
        } else if pub_key.is_a(KeyType::EC) {
            KeyAlg::Ecdsa
        } else {
            bail!("{}", t().err_key_alg)
        };
        let mut chain = vec![der.clone()];
        for c in &self.chain {
            chain.push(c.to_der()?);
        }
        Ok(SignerCert { der, issuer_der, serial_be, chain, alg })
    }

    /// Signs the SHA-256 of `data` with the entry's private key.
    fn sign(&self, data: &[u8], alg: KeyAlg) -> Result<Vec<u8>> {
        let key = self.key.as_ref().ok_or_else(|| anyhow!("{}", t().err_no_key))?;
        let mut signer = Signer::new(MessageDigest::sha256(), key).map_err(|e| anyhow!("{}: {e}", t().err_sign_refused))?;
        signer.update(data).map_err(|e| anyhow!("{}: {e}", t().err_sign_refused))?;
        let der = signer.sign_to_vec().map_err(|e| anyhow!("{}: {e}", t().err_sign_refused))?;
        match alg {
            // RSA: raw PKCS#1 v1.5 signature.
            KeyAlg::Rsa => Ok(der),
            // ECDSA: OpenSSL returns DER (SEQUENCE of two INTEGERs); CMS needs raw r||s.
            KeyAlg::Ecdsa => {
                let esig = EcdsaSig::from_der(&der).map_err(|e| anyhow!("{}: {e}", t().err_sign_refused))?;
                // Field size of the curve in bytes (P-256 -> 32); PKey::size() is the
                // max DER signature length, not the coordinate size.
                let n = (key.bits() / 8).max(1);
                let r = esig.r().to_vec_padded(n as i32).map_err(|e| anyhow!("{}: {e}", t().err_sign_refused))?;
                let s = esig.s().to_vec_padded(n as i32).map_err(|e| anyhow!("{}: {e}", t().err_sign_refused))?;
                let mut raw = r;
                raw.extend(s);
                Ok(raw)
            }
        }
    }
}

fn parse_file(path: &Path) -> Result<Entry> {
    let bytes = std::fs::read(path).with_context(|| path.display().to_string())?;
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if ext == "p12" || ext == "pfx" {
        let pass = passphrase_for(path);
        let p12 = Pkcs12::from_der(&bytes).with_context(|| path.display().to_string())?;
        let parsed = p12.parse2(&pass).with_context(|| path.display().to_string())?;
        let cert = parsed.cert.ok_or_else(|| anyhow!("{}", t().err_invalid_pdf))?;
        Ok(Entry {
            cert,
            chain: parsed.ca.into_iter().flatten().collect(),
            key: parsed.pkey,
        })
    } else {
        let certs = if ext == "der" {
            vec![X509::from_der(&bytes).with_context(|| path.display().to_string())?]
        } else {
            X509::stack_from_pem(&bytes).with_context(|| path.display().to_string())?
        };
        let Some(cert) = certs.first().cloned() else {
            bail!("{}", t().err_invalid_pdf);
        };
        let key = key_for(path)?;
        Ok(Entry { cert, chain: certs.into_iter().skip(1).collect(), key })
    }
}

/// For a certificate file, the private key is `<stem>.key` (or `.key.pem` / `.key.der`) in the same folder.
fn key_for(cert_path: &Path) -> Result<Option<PKey<Private>>> {
    let stem = cert_path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let dir = cert_path.parent().unwrap_or_else(|| Path::new("."));
    let candidates = [
        dir.join(format!("{stem}.key")),
        dir.join(format!("{stem}.key.pem")),
        dir.join(format!("{stem}.key.der")),
    ];
    let Some(kp) = candidates.iter().find(|p| p.exists()) else {
        return Ok(None);
    };
    let bytes = std::fs::read(kp).with_context(|| kp.display().to_string())?;
    let pass = passphrase_for(kp);
    // Detect an encrypted key without parsing: without a passphrase we must skip it,
    // otherwise OpenSSL falls back to a terminal UI prompt (bad in a GUI app).
    let text = String::from_utf8_lossy(&bytes);
    let encrypted = text.contains("ENCRYPTED PRIVATE KEY") || text.contains("Proc-Type: 4,ENCRYPTED");
    if encrypted && pass.is_empty() {
        return Ok(None);
    }
    let key = if encrypted {
        PKey::private_key_from_pem_passphrase(&bytes, pass.as_bytes())
            .or_else(|_| PKey::private_key_from_der(&bytes))
    } else {
        PKey::private_key_from_pem(&bytes).or_else(|_| PKey::private_key_from_der(&bytes))
    }
    .with_context(|| kp.display().to_string())?;
    Ok(Some(key))
}

fn iter_entries() -> Result<Vec<(PathBuf, Entry)>> {
    scan_dir(&certs_dir())
}

fn scan_dir(dir: &std::path::Path) -> Result<Vec<(PathBuf, Entry)>> {
    // A missing folder means "no certificates yet", not an error.
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("{}: {}", t().err_store, dir.display())),
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let path = e.path();
        if !is_cert_file(&path) {
            continue;
        }
        if let Ok(entry) = parse_file(&path) {
            out.push((path, entry));
        }
    }
    Ok(out)
}

fn display_name(n: &X509NameRef) -> String {
    let cn = n
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().to_string().ok())
        .filter(|s| !s.trim().is_empty());
    if let Some(cn) = cn {
        return cn;
    }
    n.entries()
        .filter_map(|e| {
            let field = e.object().nid().short_name().ok()?.to_string();
            let value = e.data().to_string().ok()?;
            Some(format!("{field}={value}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// OpenSSL prints X509 times as `Nov 22 14:25:30 2036 GMT` (UTCTime) or
/// `2055-01-01 00:00:00Z` (GeneralizedTime).
fn local_time(t: &Asn1TimeRef) -> chrono::DateTime<Local> {
    let s = t.to_string();
    let parsed = s
        .strip_suffix('Z')
        .and_then(|g| {
            chrono::NaiveDateTime::parse_from_str(g, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|ndt| Local.from_local_datetime(&ndt).single())
        })
        .or_else(|| {
            let g = s.strip_suffix("GMT").unwrap_or(&s).trim();
            chrono::NaiveDateTime::parse_from_str(g, "%b %d %H:%M:%S %Y")
                .ok()
                .map(|ndt| Local.from_local_datetime(&ndt).single())
        });
    parsed.flatten().unwrap_or_else(Local::now)
}

fn has_doc_signing_eku(cert: &X509) -> bool {
    cert.to_der().unwrap_or_default().windows(DOC_SIGNING_OID.len()).any(|w| w == DOC_SIGNING_OID)
}

/// All certificate files in the folder that have a private key.
pub fn list_certificates() -> Result<Vec<crate::CertInfo>> {
    let entries = iter_entries()?;
    let mut out = Vec::new();
    for (_, entry) in &entries {
        if entry.key.is_none() {
            continue;
        }
        out.push(entry.info());
    }
    out.sort_by(|a, b| {
        (b.doc_signing, b.is_valid_now(), b.not_after).cmp(&(a.doc_signing, a.is_valid_now(), a.not_after))
    });
    Ok(out)
}

fn find(thumbprint: &[u8]) -> Result<Entry> {
    let mut last_err: Option<(PathBuf, anyhow::Error)> = None;
    let dir = certs_dir();
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(anyhow!("{}", t().err_cert_not_found)),
        Err(e) => return Err(e).with_context(|| format!("{}: {}", t().err_store, dir.display())),
    };
    for e in rd.flatten() {
        let path = e.path();
        if !is_cert_file(&path) {
            continue;
        }
        match parse_file(&path) {
            Ok(entry) if entry.thumbprint() == thumbprint => return Ok(entry),
            Ok(_) => {}
            Err(err) => last_err = Some((path, err)),
        }
    }
    if let Some((p, err)) = last_err {
        bail!("{}: {err:#}", p.display());
    }
    bail!("{}", t().err_cert_not_found)
}

/// Collects the certificate, its chain and the identifiers needed for CMS.
pub fn load_signer(thumbprint: &[u8]) -> Result<SignerCert> {
    find(thumbprint)?.signer()
}

/// Signs the SHA-256 of `data` with the certificate's private key.
pub fn sign_digest(thumbprint: &[u8], data: &[u8], alg: KeyAlg) -> Result<Vec<u8>> {
    find(thumbprint)?.sign(data, alg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_dir_is_empty_not_error() {
        let dir = std::path::Path::new("/nonexistent-doc-signer-certs-test-xyz");
        assert!(scan_dir(dir).expect("missing dir is not an error").is_empty());
    }
}

