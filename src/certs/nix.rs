use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Local;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::hash::MessageDigest;
use openssl::pkey::{KeyType, PKey, Private};
use openssl::sign::Signer;
use openssl::pkcs12::Pkcs12;
use openssl::x509::{X509, X509NameRef};

use crate::cms::{KeyAlg, SignerCert};
use crate::i18n::t;

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
/// next to the key / PKCS#12 file, or empty. Like ssh, a `.pass` file that group or
/// others can read is ignored.
fn passphrase_for(path: &Path) -> String {
    if let Ok(p) = std::env::var("DOC_SIGNER_PASS") {
        if !p.is_empty() {
            return p;
        }
    }
    let mut pf = path.to_path_buf();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let _ = pf.set_file_name(format!("{name}.pass"));
    if let Ok(meta) = std::fs::metadata(&pf) {
        if !is_private_mode(meta.permissions().mode()) {
            eprintln!("doc-signer: ignoring {} - it is readable by group/others (run: chmod 600)", pf.display());
            return String::new();
        }
    }
    std::fs::read_to_string(&pf)
        .ok()
        .and_then(|s| s.lines().next().map(str::to_string))
        .unwrap_or_default()
}

fn is_private_mode(mode: u32) -> bool {
    mode & 0o077 == 0
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
        let (not_before, not_after) = validity(&self.cert);
        crate::CertInfo {
            subject: display_name(self.cert.subject_name()),
            issuer: display_name(self.cert.issuer_name()),
            not_before,
            not_after,
            thumbprint: self.thumbprint(),
            doc_signing: self.cert.to_der().is_ok_and(|der| super::has_doc_signing_eku(&der)),
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
        let cert = parsed.cert.ok_or_else(|| anyhow!("{}: {}", t().err_invalid_cert, path.display()))?;
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
            bail!("{}: {}", t().err_invalid_cert, path.display());
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

/// X.509 times are always UTC (RFC 5280 §4.1.2.5). The instant is taken from OpenSSL's own
/// `ASN1_TIME_diff` against the Unix epoch, so no string parsing and no local-time interpretation
/// is involved. `None` if OpenSSL cannot interpret the time.
fn local_time(t: &Asn1TimeRef) -> Option<chrono::DateTime<Local>> {
    let epoch = Asn1Time::from_unix(0).ok()?;
    let d = epoch.diff(t).ok()?;
    let secs = i64::from(d.days) * 86_400 + i64::from(d.secs);
    chrono::DateTime::from_timestamp(secs, 0).map(|utc| utc.with_timezone(&Local))
}

/// Validity period; an unreadable one is reported as expired at the epoch (fail closed), so such a
/// certificate is never offered as valid.
fn validity(cert: &X509) -> (chrono::DateTime<Local>, chrono::DateTime<Local>) {
    match (local_time(cert.not_before()), local_time(cert.not_after())) {
        (Some(nb), Some(na)) => (nb, na),
        _ => {
            let epoch = chrono::DateTime::UNIX_EPOCH.with_timezone(&Local);
            (epoch, epoch)
        }
    }
}

/// Parsed (and decrypted) entries by thumbprint, so batch signing does not re-read and
/// re-decrypt every file in the folder for each document. Cleared by `list_certificates`
/// (the UI's refresh), which picks up changed files.
fn cache() -> std::sync::MutexGuard<'static, HashMap<Vec<u8>, Arc<Entry>>> {
    static CACHE: OnceLock<Mutex<HashMap<Vec<u8>, Arc<Entry>>>> = OnceLock::new();
    CACHE.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// All certificate files in the folder that have a private key.
/// Certificates of the system CA bundle (`SSL_CERT_FILE` or the usual distribution paths).
pub fn root_store_certs() -> Vec<Vec<u8>> {
    let candidates = [
        std::env::var("SSL_CERT_FILE").unwrap_or_default(),
        "/etc/ssl/certs/ca-certificates.crt".into(),
        "/etc/pki/tls/certs/ca-bundle.crt".into(),
        "/etc/ssl/ca-bundle.pem".into(),
        "/etc/ssl/cert.pem".into(),
    ];
    let Some(pem) = candidates.iter().filter(|p| !p.is_empty()).find_map(|p| std::fs::read(p).ok()) else { return Vec::new() };
    X509::stack_from_pem(&pem).map(|certs| certs.iter().filter_map(|c| c.to_der().ok()).collect()).unwrap_or_default()
}

pub fn list_certificates() -> Result<Vec<crate::CertInfo>> {
    cache().clear();
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

fn find(thumbprint: &[u8]) -> Result<Arc<Entry>> {
    if let Some(e) = cache().get(thumbprint) {
        return Ok(e.clone());
    }
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
            Ok(entry) if entry.thumbprint() == thumbprint => {
                let entry = Arc::new(entry);
                cache().insert(thumbprint.to_vec(), entry.clone());
                return Ok(entry);
            }
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
pub fn sign_data(thumbprint: &[u8], data: &[u8], alg: KeyAlg) -> Result<Vec<u8>> {
    find(thumbprint)?.sign(data, alg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_files_must_not_be_group_or_world_readable() {
        assert!(is_private_mode(0o100600));
        assert!(is_private_mode(0o100400));
        assert!(!is_private_mode(0o100640));
        assert!(!is_private_mode(0o100644));
        assert!(!is_private_mode(0o100604));
    }

    #[test]
    fn missing_dir_is_empty_not_error() {
        let dir = std::path::Path::new("/nonexistent-doc-signer-certs-test-xyz");
        assert!(scan_dir(dir).expect("missing dir is not an error").is_empty());
    }

    /// X.509 times are UTC: the instant must not depend on the local timezone.
    #[test]
    fn certificate_times_are_utc_instants() {
        // A non-UTC zone (POSIX TZ string, no tz database needed) exposes local-time misparsing.
        unsafe { std::env::set_var("TZ", "EET-2") };
        let utc_time = Asn1Time::from_str("300101000000Z").unwrap(); // UTCTime
        let gen_time = Asn1Time::from_str("20550101120000Z").unwrap(); // GeneralizedTime
        assert_eq!(local_time(&utc_time).unwrap().timestamp(), 1_893_456_000);
        assert_eq!(local_time(&gen_time).unwrap().timestamp(), 2_682_417_600);
    }
}

