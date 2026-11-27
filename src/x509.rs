//! Just enough X.509 parsing for collecting validation data: names, serial, public key and the
//! AIA / CRL distribution point URLs.

use crate::cms::read_tlv;

const OID_AIA: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]; // 1.3.6.1.5.5.7.1.1
const OID_CRL_DP: &[u8] = &[0x55, 0x1D, 0x1F]; // 2.5.29.31
const OID_OCSP: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]; // 1.3.6.1.5.5.7.48.1
const OID_CA_ISSUERS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]; // 1.3.6.1.5.5.7.48.2
const OID_OCSP_NOCHECK: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05]; // 1.3.6.1.5.5.7.48.1.5

#[derive(Clone, Debug, Default)]
pub struct Cert {
    pub der: Vec<u8>,
    /// INTEGER content bytes as encoded (may have a leading zero).
    pub serial: Vec<u8>,
    /// Full DER of the issuer / subject Name.
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    /// subjectPublicKey BIT STRING without the unused-bits byte (input of the OCSP key hash).
    pub public_key: Vec<u8>,
    pub ocsp_urls: Vec<String>,
    pub ca_issuer_urls: Vec<String>,
    pub crl_urls: Vec<String>,
    /// The certificate is an OCSP responder that needs no revocation check itself.
    pub ocsp_nocheck: bool,
}

impl Cert {
    pub fn self_issued(&self) -> bool {
        self.issuer == self.subject
    }

    /// Common name for messages, or the whole subject as a fallback.
    pub fn name(&self) -> String {
        name_cn(&self.subject).unwrap_or_else(|| "?".into())
    }
}

/// Full TLV (tag + length + content) at the front of `b`.
fn whole(b: &[u8]) -> Option<&[u8]> {
    let (_, _, rest) = read_tlv(b)?;
    Some(&b[..b.len() - rest.len()])
}

pub fn parse(der: &[u8]) -> Option<Cert> {
    let (tag, cert, _) = read_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (_, tbs, _) = read_tlv(cert).filter(|t| t.0 == 0x30)?;
    let mut rest = tbs;
    if rest.first() == Some(&0xA0) {
        rest = read_tlv(rest)?.2;
    }
    let (_, serial, r) = read_tlv(rest).filter(|t| t.0 == 0x02)?;
    let (_, _, r) = read_tlv(r)?; // signature algorithm
    let issuer = whole(r)?;
    let (_, _, r) = read_tlv(r)?;
    let (_, _, r) = read_tlv(r)?; // validity
    let subject = whole(r)?;
    let (_, _, r) = read_tlv(r)?;
    let (_, spki, mut r) = read_tlv(r).filter(|t| t.0 == 0x30)?;
    let (_, _, spki) = read_tlv(spki)?; // algorithm
    let (_, key, _) = read_tlv(spki).filter(|t| t.0 == 0x03)?;
    let mut c = Cert {
        der: whole(der)?.to_vec(),
        serial: serial.to_vec(),
        issuer: issuer.to_vec(),
        subject: subject.to_vec(),
        public_key: key.get(1..)?.to_vec(),
        ..Default::default()
    };
    while let Some((tag, v, next)) = read_tlv(r) {
        if tag == 0xA3 {
            let (_, mut exts, _) = read_tlv(v).filter(|t| t.0 == 0x30)?;
            while let Some((_, ext, more)) = read_tlv(exts) {
                extension(&mut c, ext);
                exts = more;
            }
        }
        r = next;
    }
    Some(c)
}

fn extension(c: &mut Cert, ext: &[u8]) {
    let Some((_, id, mut r)) = read_tlv(ext).filter(|t| t.0 == 0x06) else { return };
    if r.first() == Some(&0x01) {
        r = read_tlv(r).map(|t| t.2).unwrap_or_default(); // critical
    }
    let Some((_, value, _)) = read_tlv(r).filter(|t| t.0 == 0x04) else { return };
    match id {
        OID_AIA => {
            let Some((_, mut list, _)) = read_tlv(value) else { return };
            while let Some((_, ad, more)) = read_tlv(list) {
                if let Some((_, method, name)) = read_tlv(ad) {
                    let urls = if method == OID_OCSP {
                        Some(&mut c.ocsp_urls)
                    } else if method == OID_CA_ISSUERS {
                        Some(&mut c.ca_issuer_urls)
                    } else {
                        None
                    };
                    if let (Some(urls), Some(url)) = (urls, uri(name)) {
                        urls.push(url);
                    }
                }
                list = more;
            }
        }
        OID_CRL_DP => {
            let Some((_, mut list, _)) = read_tlv(value) else { return };
            while let Some((_, dp, more)) = read_tlv(list) {
                // DistributionPoint { [0] { [0] fullName GeneralNames } }
                if let Some((_, full, _)) = read_tlv(dp).filter(|t| t.0 == 0xA0).and_then(|(_, n, _)| read_tlv(n)).filter(|t| t.0 == 0xA0) {
                    let mut names = full;
                    while let Some((_, _, next)) = read_tlv(names) {
                        if let Some(url) = uri(names) {
                            c.crl_urls.push(url);
                        }
                        names = next;
                    }
                }
                list = more;
            }
        }
        OID_OCSP_NOCHECK => c.ocsp_nocheck = true,
        _ => {}
    }
}

/// GeneralName uniformResourceIdentifier ([6] IA5String).
fn uri(general_name: &[u8]) -> Option<String> {
    let (tag, v, _) = read_tlv(general_name)?;
    (tag == 0x86).then(|| String::from_utf8_lossy(v).into_owned())
}

/// CN of a DER Name.
fn name_cn(name: &[u8]) -> Option<String> {
    let (_, mut rdns, _) = read_tlv(name)?;
    let mut cn = None;
    while let Some((_, rdn, more)) = read_tlv(rdns) {
        let (_, atv, _) = read_tlv(rdn)?;
        let (_, oid, v) = read_tlv(atv)?;
        if oid == [0x55, 0x04, 0x03] {
            cn = read_tlv(v).map(|(_, s, _)| String::from_utf8_lossy(s).into_owned());
        }
        rdns = more;
    }
    cn
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Certificate of the pyHanko test fixture signer (issued by a test CA with AIA and CRL DP).
    fn fixture_certs() -> Vec<Vec<u8>> {
        let pdf = include_bytes!("../tests/fixtures/signed-by-pyhanko.pdf");
        let start = pdf.windows(11).position(|w| w == b"/Contents <").unwrap() + 11;
        let hex: Vec<u8> = pdf[start..].iter().take_while(|&&c| c != b'>').copied().collect();
        let der: Vec<u8> = hex.chunks(2).map(|h| u8::from_str_radix(std::str::from_utf8(h).unwrap(), 16).unwrap()).collect();
        crate::cms::certificates(&der)
    }

    #[test]
    fn parses_names_keys_and_urls() {
        let certs: Vec<Cert> = fixture_certs().iter().map(|d| parse(d).expect("certificate parses")).collect();
        assert!(!certs.is_empty());
        for c in &certs {
            assert!(!c.serial.is_empty() && !c.public_key.is_empty());
            assert_eq!(c.der, *fixture_certs().iter().find(|d| **d == c.der).unwrap());
        }
        assert!(certs.iter().any(|c| c.name().contains("Fixture Signer")), "{:?}", certs.iter().map(|c| c.name()).collect::<Vec<_>>());
    }

    #[test]
    fn reads_aia_and_crl_urls() {
        // Minimal TBS with only the two extensions; outer structure as in a real certificate.
        let t = |tag: u8, v: &[u8]| crate::cms::tlv(tag, v);
        let seq = |parts: &[&[u8]]| t(0x30, &parts.concat());
        let name = seq(&[&t(0x31, &seq(&[&t(0x06, &[0x55, 0x04, 0x03]), &t(0x0C, b"Test CA")]))]);
        let aia = seq(&[&seq(&[&t(0x06, OID_OCSP), &t(0x86, b"http://ocsp.example")]), &seq(&[&t(0x06, OID_CA_ISSUERS), &t(0x86, b"http://ca.example/ca.crt")])]);
        let crldp = seq(&[&seq(&[&t(0xA0, &t(0xA0, &[t(0x86, b"ldap:///skip").as_slice(), t(0x86, b"http://ca.example/a b.crl").as_slice()].concat()))])]);
        let exts = seq(&[&seq(&[&t(0x06, OID_AIA), &t(0x04, &aia)]), &seq(&[&t(0x06, OID_CRL_DP), &t(0x01, &[0xFF]), &t(0x04, &crldp)]), &seq(&[&t(0x06, OID_OCSP_NOCHECK), &t(0x04, &[0x05, 0x00])])]);
        let spki = seq(&[&seq(&[&t(0x06, &[0x2A])]), &t(0x03, &[0x00, 1, 2, 3])]);
        let tbs = seq(&[&t(0xA0, &t(0x02, &[2])), &t(0x02, &[0x00, 0x9F]), &seq(&[&t(0x06, &[0x2A])]), &name, &seq(&[]), &name, &spki, &t(0xA3, &exts)]);
        let der = seq(&[&tbs, &seq(&[&t(0x06, &[0x2A])]), &t(0x03, &[0x00])]);
        let c = parse(&der).unwrap();
        assert_eq!(c.ocsp_urls, ["http://ocsp.example"]);
        assert_eq!(c.ca_issuer_urls, ["http://ca.example/ca.crt"]);
        assert_eq!(c.crl_urls, ["ldap:///skip", "http://ca.example/a b.crl"]);
        assert!(c.ocsp_nocheck && c.self_issued());
        assert_eq!(c.serial, [0x00, 0x9F]);
        assert_eq!(c.public_key, [1, 2, 3]);
        assert_eq!(c.name(), "Test CA");
    }
}
