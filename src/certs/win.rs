use std::ffi::c_void;
use std::ptr::null_mut;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Local, TimeZone};
use sha2::Digest;
use windows::Win32::Security::Cryptography::*;
use windows::core::w;

use crate::cms::{KeyAlg, SignerCert};
use crate::i18n::t;

struct Store(HCERTSTORE);

impl Store {
    fn open_my() -> Result<Self> {
        let h = unsafe { CertOpenSystemStoreW(None, w!("MY")) }.context(t().err_store)?;
        Ok(Store(h))
    }

    fn find(&self, thumbprint: &[u8]) -> Result<Cert> {
        let blob = CRYPT_INTEGER_BLOB { cbData: thumbprint.len() as u32, pbData: thumbprint.as_ptr() as *mut u8 };
        let ctx = unsafe {
            CertFindCertificateInStore(
                self.0,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_HASH,
                Some(&blob as *const _ as *const c_void),
                None,
            )
        };
        if ctx.is_null() {
            bail!(t().err_cert_not_found);
        }
        Ok(Cert(ctx))
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(Some(self.0), 0);
        }
    }
}

struct Cert(*mut CERT_CONTEXT);

impl Drop for Cert {
    fn drop(&mut self) {
        unsafe {
            let _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}

fn filetime_to_local(ft: &windows::Win32::Foundation::FILETIME) -> DateTime<Local> {
    let ticks = ((ft.dwHighDateTime as i64) << 32) | ft.dwLowDateTime as i64;
    let secs = (ticks - 116_444_736_000_000_000) / 10_000_000;
    Local.timestamp_opt(secs, 0).single().unwrap_or_else(Local::now)
}

unsafe fn name_string(ctx: *const CERT_CONTEXT, flags: u32) -> String {
    unsafe {
        let n = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None);
        let mut buf = vec![0u16; n as usize];
        CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, Some(&mut buf));
        String::from_utf16_lossy(&buf[..buf.len().saturating_sub(1)])
    }
}

unsafe fn encoded(ctx: *const CERT_CONTEXT) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize).to_vec() }
}

unsafe fn has_private_key(ctx: *const CERT_CONTEXT) -> bool {
    let mut size = 0u32;
    unsafe { CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, None, &mut size).is_ok() }
}

/// Certificates of the trusted root store (CurrentUser\Root, which includes the machine's roots).
pub fn root_store_certs() -> Vec<Vec<u8>> {
    let Ok(h) = (unsafe { CertOpenSystemStoreW(None, w!("ROOT")) }) else { return Vec::new() };
    let store = Store(h);
    let mut out = Vec::new();
    let mut ctx: *mut CERT_CONTEXT = null_mut();
    loop {
        ctx = unsafe { CertEnumCertificatesInStore(store.0, if ctx.is_null() { None } else { Some(ctx) }) };
        if ctx.is_null() {
            break;
        }
        out.push(unsafe { encoded(ctx) });
    }
    out
}

/// Personal certificates (CurrentUser\My) that have a private key.
pub fn list_certificates() -> Result<Vec<crate::CertInfo>> {
    let store = Store::open_my()?;
    let mut out = Vec::new();
    let mut ctx: *mut CERT_CONTEXT = null_mut();
    loop {
        ctx = unsafe { CertEnumCertificatesInStore(store.0, if ctx.is_null() { None } else { Some(ctx) }) };
        if ctx.is_null() {
            break;
        }
        unsafe {
            if !has_private_key(ctx) {
                continue;
            }
            let info = &*(*ctx).pCertInfo;
            let mut thumb = vec![0u8; 20];
            let mut len = 20u32;
            if CertGetCertificateContextProperty(ctx, CERT_HASH_PROP_ID, Some(thumb.as_mut_ptr() as *mut c_void), &mut len).is_err() {
                continue;
            }
            let der = encoded(ctx);
            out.push(crate::CertInfo {
                subject: name_string(ctx, 0),
                issuer: name_string(ctx, CERT_NAME_ISSUER_FLAG),
                not_before: filetime_to_local(&info.NotBefore),
                not_after: filetime_to_local(&info.NotAfter),
                thumbprint: thumb,
                doc_signing: super::has_doc_signing_eku(&der),
            });
        }
    }
    out.sort_by(|a, b| {
        (b.doc_signing, b.is_valid_now(), b.not_after).cmp(&(a.doc_signing, a.is_valid_now(), a.not_after))
    });
    Ok(out)
}

/// Collects the certificate, its chain and the identifiers needed for CMS.
pub fn load_signer(thumbprint: &[u8]) -> Result<SignerCert> {
    let store = Store::open_my()?;
    let cert = store.find(thumbprint)?;
    unsafe {
        let ctx = cert.0;
        let info = &*(*ctx).pCertInfo;
        let issuer_der = std::slice::from_raw_parts(info.Issuer.pbData, info.Issuer.cbData as usize).to_vec();
        let mut serial_be = std::slice::from_raw_parts(info.SerialNumber.pbData, info.SerialNumber.cbData as usize).to_vec();
        serial_be.reverse();
        let alg_oid = info.SubjectPublicKeyInfo.Algorithm.pszObjId.to_string().unwrap_or_default();
        let alg = match alg_oid.as_str() {
            "1.2.840.113549.1.1.1" => KeyAlg::Rsa,
            "1.2.840.10045.2.1" => KeyAlg::Ecdsa,
            other => bail!("{}: {other}", t().err_key_alg),
        };
        let der = encoded(ctx);

        let mut chain_certs = vec![der.clone()];
        let para = CERT_CHAIN_PARA { cbSize: size_of::<CERT_CHAIN_PARA>() as u32, ..Default::default() };
        let mut chain: *mut CERT_CHAIN_CONTEXT = null_mut();
        if CertGetCertificateChain(None, ctx, None, None, &para, 0, None, &mut chain).is_ok() && !chain.is_null() {
            if (*chain).cChain > 0 {
                let simple = *(*chain).rgpChain;
                for i in 1..(*simple).cElement as usize {
                    let el = *(*simple).rgpElement.add(i);
                    chain_certs.push(encoded((*el).pCertContext));
                }
            }
            CertFreeCertificateChain(chain);
        }

        Ok(SignerCert { der, issuer_der, serial_be, chain: chain_certs, alg })
    }
}

/// RSA PKCS#1 v1.5 signature of a SHA-256 `digest` with a legacy CryptoAPI (CSP) key.
unsafe fn sign_csp(prov: usize, spec: CERT_KEY_SPEC, digest: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut hash = 0usize;
        // Fails for providers without SHA-256 (e.g. PROV_RSA_FULL "Base"/"Enhanced" CSPs).
        CryptCreateHash(prov, CALG_SHA_256, 0, 0, &mut hash).map_err(|e| anyhow!("{}: {e}", t().err_csp_sha256))?;
        let result = CryptSetHashParam(hash, HP_HASHVAL, digest.as_ptr(), 0).and_then(|_| {
            let mut len = 0u32;
            CryptSignHashW(hash, spec.0, None, 0, None, &mut len)?;
            let mut sig = vec![0u8; len as usize];
            CryptSignHashW(hash, spec.0, None, 0, Some(sig.as_mut_ptr()), &mut len)?;
            sig.truncate(len as usize);
            // CryptoAPI returns the signature little-endian.
            sig.reverse();
            Ok(sig)
        });
        let _ = CryptDestroyHash(hash);
        result.map_err(|e| anyhow!("{}: {e}", t().err_sign_refused))
    }
}

/// Signs the SHA-256 of `data` with the certificate's private key (may show a PIN prompt for smart cards).
/// CNG keys use NCrypt (RSA or ECDSA); legacy CryptoAPI (CSP) keys use CryptSignHash (RSA only).
pub fn sign_data(thumbprint: &[u8], data: &[u8], alg: KeyAlg) -> Result<Vec<u8>> {
    let digest = sha2::Sha256::digest(data);
    let store = Store::open_my()?;
    let cert = store.find(thumbprint)?;
    unsafe {
        let mut key = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut spec = CERT_KEY_SPEC(0);
        let mut must_free = windows::core::BOOL(0);
        CryptAcquireCertificatePrivateKey(
            cert.0,
            CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
            None,
            &mut key,
            Some(&mut spec),
            Some(&mut must_free),
        )
        .context(t().err_no_key)?;
        if spec != CERT_NCRYPT_KEY_SPEC {
            let prov = key.0;
            let result = if alg == KeyAlg::Rsa { sign_csp(prov, spec, &digest) } else { Err(anyhow!("{}", t().err_not_cng)) };
            if must_free.as_bool() {
                let _ = CryptReleaseContext(prov, 0);
            }
            return result;
        }
        let hkey = NCRYPT_KEY_HANDLE(key.0);

        let padding = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM };
        let (pad_ptr, flags) = match alg {
            KeyAlg::Rsa => (Some(&padding as *const _ as *const c_void), NCRYPT_PAD_PKCS1_FLAG),
            KeyAlg::Ecdsa => (None, NCRYPT_FLAGS(0)),
        };
        let mut len = 0u32;
        let result = NCryptSignHash(hkey, pad_ptr, &digest, None, &mut len, flags).and_then(|_| {
            let mut sig = vec![0u8; len as usize];
            NCryptSignHash(hkey, pad_ptr, &digest, Some(&mut sig), &mut len, flags).map(|_| {
                sig.truncate(len as usize);
                sig
            })
        });
        if must_free.as_bool() {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(hkey.0));
        }
        result.map_err(|e| anyhow!("{}: {e}", t().err_sign_refused))
    }
}


/// Verifies a PKCS#1 v1.5 (RSA) or DER-encoded ECDSA `signature` over a precomputed `digest`
/// with the public key of `cert_der`.
pub fn verify_digest(cert_der: &[u8], hash: super::HashAlg, digest: &[u8], signature: &[u8]) -> Result<bool> {
    unsafe {
        let ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_der);
        if ctx.is_null() {
            bail!("invalid certificate");
        }
        let cert = Cert(ctx);
        let info = &*(*cert.0).pCertInfo;
        let mut key = BCRYPT_KEY_HANDLE::default();
        CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &info.SubjectPublicKeyInfo, CRYPT_IMPORT_PUBLIC_KEY_FLAGS(0), None, &mut key)?;
        let alg_oid = info.SubjectPublicKeyInfo.Algorithm.pszObjId.to_string().unwrap_or_default();
        let ok = if alg_oid == "1.2.840.10045.2.1" {
            // CNG wants r || s, each as long as the key.
            let mut bits = [0u8; 4];
            let mut got = 0u32;
            let _ = BCryptGetProperty(key.into(), BCRYPT_KEY_LENGTH, Some(&mut bits), &mut got, 0);
            let n = (u32::from_le_bytes(bits) as usize).div_ceil(8);
            match super::ecdsa_der_to_raw(signature, n) {
                Some(raw) => BCryptVerifySignature(key, None, digest, &raw, BCRYPT_FLAGS(0)).is_ok(),
                None => false,
            }
        } else {
            let alg = match hash {
                super::HashAlg::Sha1 => BCRYPT_SHA1_ALGORITHM,
                super::HashAlg::Sha256 => BCRYPT_SHA256_ALGORITHM,
                super::HashAlg::Sha384 => BCRYPT_SHA384_ALGORITHM,
                super::HashAlg::Sha512 => BCRYPT_SHA512_ALGORITHM,
            };
            let padding = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: alg };
            BCryptVerifySignature(key, Some(&padding as *const _ as *const c_void), digest, signature, BCRYPT_PAD_PKCS1).is_ok()
        };
        let _ = BCryptDestroyKey(key);
        Ok(ok)
    }
}

/// Builds the chain of `cert_der` with the help of `extra` certificates, as of `at`, and checks
/// it against the Windows trust store. Revocation is not checked.
pub fn check_chain(cert_der: &[u8], extra: &[Vec<u8>], at: chrono::DateTime<chrono::Utc>) -> Result<super::Chain> {
    use super::ChainProblem as P;
    unsafe {
        let store = Store(CertOpenStore(CERT_STORE_PROV_MEMORY, CERT_QUERY_ENCODING_TYPE(0), None, CERT_OPEN_STORE_FLAGS(0), None)?);
        for c in extra {
            let _ = CertAddEncodedCertificateToStore(Some(store.0), X509_ASN_ENCODING, c, CERT_STORE_ADD_USE_EXISTING, None);
        }
        let mut leaf: *mut CERT_CONTEXT = null_mut();
        CertAddEncodedCertificateToStore(Some(store.0), X509_ASN_ENCODING, cert_der, CERT_STORE_ADD_USE_EXISTING, Some(&mut leaf))?;
        let leaf = Cert(leaf);
        let ticks = at.timestamp() * 10_000_000 + 116_444_736_000_000_000;
        let ft = windows::Win32::Foundation::FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
        let para = CERT_CHAIN_PARA { cbSize: size_of::<CERT_CHAIN_PARA>() as u32, ..Default::default() };
        let mut chain: *mut CERT_CHAIN_CONTEXT = null_mut();
        // Cache-only retrieval: no network access while verifying.
        CertGetCertificateChain(None, leaf.0, Some(&ft), Some(store.0), &para, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, None, &mut chain)?;
        let status = (*chain).TrustStatus.dwErrorStatus;
        let mut names = Vec::new();
        if (*chain).cChain > 0 {
            let simple = *(*chain).rgpChain;
            for i in 0..(*simple).cElement as usize {
                let el = *(*simple).rgpElement.add(i);
                names.push(name_string((*el).pCertContext, 0));
            }
        }
        CertFreeCertificateChain(chain);
        let mut problems = Vec::new();
        if status & 0x1 != 0 {
            problems.push(P::NotTimeValid);
        }
        if status & 0x4 != 0 {
            problems.push(P::Revoked);
        }
        if status & 0x8 != 0 {
            problems.push(P::BadSignature);
        }
        if status & 0x20 != 0 {
            problems.push(P::UntrustedRoot);
        }
        if status & 0x10000 != 0 {
            problems.push(P::PartialChain);
        }
        // Usage, policy and constraint errors; revocation-unknown (0x40, 0x1000000) is expected.
        let known = 0x1 | 0x4 | 0x8 | 0x20 | 0x10000 | 0x40 | 0x1000000;
        if status & !known != 0 {
            problems.push(P::Other(format!("0x{:08X}", status & !known)));
        }
        Ok(super::Chain { names, problems })
    }
}
