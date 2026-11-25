use std::ffi::c_void;
use std::ptr::null_mut;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Local};
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

/// Personal certificates (CurrentUser\My) that have a private key.
pub fn list_certificates() -> Result<Vec<crate::CertInfo>> {
    // DER of OID 1.3.6.1.4.1.311.10.3.12 (Microsoft Document Signing EKU).
    const DOC_SIGNING_EKU: [u8; 12] = [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x0C];
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
                doc_signing: der.windows(DOC_SIGNING_EKU.len()).any(|w| w == DOC_SIGNING_EKU),
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

/// Signs the SHA-256 of `data` with the certificate's private key (may show a PIN prompt for smart cards).
pub fn sign_digest(thumbprint: &[u8], data: &[u8], alg: KeyAlg) -> Result<Vec<u8>> {
    let digest = sha2::Sha256::digest(data);
    let store = Store::open_my()?;
    let cert = store.find(thumbprint)?;
    unsafe {
        let mut key = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut spec = CERT_KEY_SPEC(0);
        let mut must_free = windows::core::BOOL(0);
        CryptAcquireCertificatePrivateKey(
            cert.0,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            None,
            &mut key,
            Some(&mut spec),
            Some(&mut must_free),
        )
        .context(t().err_no_key)?;
        if spec != CERT_NCRYPT_KEY_SPEC {
            bail!(t().err_not_cng);
        }
        let hkey = NCRYPT_KEY_HANDLE(key.0);

        let padding = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM };
        let (pad_ptr, flags) = match alg {
            KeyAlg::Rsa => (Some(&padding as *const _ as *const c_void), NCRYPT_PAD_PKCS1_FLAG),
            KeyAlg::Ecdsa => (None, NCRYPT_FLAGS(0)),
        };
        let mut len = 0u32;
        let result = NCryptSignHash(hkey, pad_ptr, digest, None, &mut len, flags).and_then(|_| {
            let mut sig = vec![0u8; len as usize];
            NCryptSignHash(hkey, pad_ptr, digest, Some(&mut sig), &mut len, flags).map(|_| {
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

