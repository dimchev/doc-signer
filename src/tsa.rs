//! RFC 3161 time-stamp client: sends only a hash to the time-stamp authority (TSA).

use std::time::Duration;

use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};

use crate::cms;
use crate::i18n::t;

pub const DEFAULT_URL: &str = "http://timestamp.digicert.com";
const MAX_RESPONSE: u64 = 256 * 1024;

/// Unique per request; it only has to prevent replays, not be secret.
fn nonce() -> [u8; 8] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let seed = format!("{:?}{}{}", std::time::SystemTime::now(), std::process::id(), N.fetch_add(1, Ordering::Relaxed));
    let h = Sha256::digest(seed.as_bytes());
    let mut n = [0u8; 8];
    n.copy_from_slice(&h[..8]);
    n[0] &= 0x7f; // positive INTEGER without a leading zero byte
    n
}

pub(crate) fn agent() -> ureq::Agent {
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    // System TLS (Schannel / OpenSSL) with the system trust store and proxy, so corporate CAs work.
    let tls = TlsConfig::builder().provider(TlsProvider::NativeTls).root_certs(RootCerts::PlatformVerifier).build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .proxy(ureq::Proxy::try_from_env())
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(true)
        .build()
        .into()
}

/// Requests a time-stamp token for `SHA-256(data)` from `url`.
pub fn timestamp(url: &str, data: &[u8]) -> Result<cms::TimeStamp> {
    timestamp_digest(url, &Sha256::digest(data))
}

/// Requests a time-stamp token for an already computed SHA-256 `digest`.
pub fn timestamp_digest(url: &str, digest: &[u8]) -> Result<cms::TimeStamp> {
    let err = |e: &dyn std::fmt::Display| anyhow!("{} ({url}): {e}", t().err_tsa);
    let nonce = nonce();
    let req = cms::timestamp_request(digest, &nonce);
    let mut resp = agent()
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .send(&req[..])
        .map_err(|e| err(&e))?;
    let body = resp.body_mut().with_config().limit(MAX_RESPONSE).read_to_vec().map_err(|e| err(&e))?;
    cms::parse_timestamp_response(&body, digest, &nonce).map_err(|e| err(&e))
}
