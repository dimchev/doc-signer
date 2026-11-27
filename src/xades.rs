//! XAdES baseline signatures (ETSI EN 319 132-1) for XML documents: enveloped (the signature is
//! added to the document) or detached (a separate signature file referencing the data file).
//! XAdES-B-B, or XAdES-B-T with a signature time-stamp.

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::asic::{mime_type, uri_encode, xml_escape};
use crate::cms::{KeyAlg, SignerCert};
use crate::pdf::Timestamper;
use crate::xml::{self, C14n, EXC_C14N};

pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const NS_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// `<ds:Signature>` as the last child of the document element.
    Enveloped,
    /// A separate signature document; the data file is referenced by its name.
    Detached,
}

/// Format used for XML files in the UI.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum XmlFormat {
    Enveloped,
    Detached,
    /// Like any other file (CAdES `.p7s` / `.p7m` / ASiC-E).
    Cades,
}

impl XmlFormat {
    pub fn code(self) -> &'static str {
        match self {
            XmlFormat::Enveloped => "enveloped",
            XmlFormat::Detached => "detached",
            XmlFormat::Cades => "cades",
        }
    }

    pub fn from_code(s: &str) -> XmlFormat {
        match s {
            "detached" => XmlFormat::Detached,
            "cades" => XmlFormat::Cades,
            _ => XmlFormat::Enveloped,
        }
    }
}

pub fn is_xml(path: &std::path::Path) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("xml"))
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Unique-enough ids for the signature's elements.
fn new_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let seed = format!("{:?}{}{}", std::time::SystemTime::now(), std::process::id(), N.fetch_add(1, Ordering::Relaxed));
    let h = Sha256::digest(seed.as_bytes());
    format!("id-{}", h[..10].iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Exclusive canonical form of the element with `Id` = `id` in `xml_text`.
fn canonical_by_id(xml_text: &str, id: &str) -> Result<Vec<u8>> {
    let doc = xml::parse(xml_text.as_bytes())?;
    let node = doc.by_id(id).ok_or_else(|| anyhow!("XAdES: element {id} not found"))?;
    Ok(xml::canonicalize(&doc, node, &C14n { exclusive: true, ..Default::default() }, None))
}

fn canonical_first(xml_text: &str, ns: &str, local: &str) -> Result<Vec<u8>> {
    let doc = xml::parse(xml_text.as_bytes())?;
    let node = doc.descendants(0).into_iter().find(|&n| doc.is(n, ns, local)).ok_or_else(|| anyhow!("XAdES: {local} not found"))?;
    Ok(xml::canonicalize(&doc, node, &C14n { exclusive: true, ..Default::default() }, None))
}

/// Builds the `<ds:Signature>` element (as text). `data_ref` is the reference to the signed data:
/// (URI, transforms, SHA-256 digest, MIME type).
fn build_signature(data_uri: &str, enveloped: bool, data_digest: &[u8], mime: &str, signer: &SignerCert, sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>, timestamp: Option<Timestamper>) -> Result<String> {
    let (sid, rid, pid, vid, tid) = (new_id(), new_id(), new_id(), new_id(), new_id());
    let sig_alg = match signer.alg {
        KeyAlg::Rsa => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        KeyAlg::Ecdsa => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    };
    let time = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let cert_digest = b64(&Sha256::digest(&signer.der));
    let props = format!(
        concat!(
            r#"<xades:SignedProperties Id="{pid}"><xades:SignedSignatureProperties><xades:SigningTime>{time}</xades:SigningTime>"#,
            r#"<xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="{sha}"/><ds:DigestValue>{cd}</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2>"#,
            r##"</xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference="#{rid}"><xades:MimeType>{mime}</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties>"##
        ),
        pid = pid,
        time = time,
        sha = SHA256,
        cd = cert_digest,
        rid = rid,
        mime = mime,
    );
    let transforms = if enveloped { format!(r#"<ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms>"#) } else { String::new() };
    let signed_info = |props_digest: &str| {
        format!(
            concat!(
                r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{exc}"/><ds:SignatureMethod Algorithm="{alg}"/>"#,
                r#"<ds:Reference Id="{rid}" URI="{uri}">{tr}<ds:DigestMethod Algorithm="{sha}"/><ds:DigestValue>{dd}</ds:DigestValue></ds:Reference>"#,
                r##"<ds:Reference Type="{sp}" URI="#{pid}"><ds:Transforms><ds:Transform Algorithm="{exc}"/></ds:Transforms><ds:DigestMethod Algorithm="{sha}"/><ds:DigestValue>{pd}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
            ),
            exc = EXC_C14N,
            alg = sig_alg,
            rid = rid,
            uri = xml_escape(data_uri),
            tr = transforms,
            sha = SHA256,
            dd = b64(data_digest),
            sp = SIGNED_PROPERTIES,
            pid = pid,
            pd = props_digest,
        )
    };
    let key_info: String = signer.chain.iter().map(|c| format!("<ds:X509Certificate>{}</ds:X509Certificate>", b64(c))).collect();
    let assemble = |si: &str, value: &str, unsigned: &str| {
        format!(
            r##"<ds:Signature xmlns:ds="{NS_DS}" Id="{sid}">{si}<ds:SignatureValue Id="{vid}">{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data>{key_info}</ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties xmlns:xades="{NS_XADES}" Target="#{sid}">{props}{unsigned}</xades:QualifyingProperties></ds:Object></ds:Signature>"##
        )
    };

    let props_digest = b64(&Sha256::digest(canonical_by_id(&assemble(&signed_info(""), "", ""), &pid)?));
    let si = signed_info(&props_digest);
    let si_c14n = canonical_first(&assemble(&si, "", ""), NS_DS, "SignedInfo")?;
    let value = b64(&sign(&si_c14n)?);
    let mut unsigned = String::new();
    if let Some(ts) = timestamp {
        let value_c14n = canonical_by_id(&assemble(&si, &value, ""), &vid)?;
        let token = ts(&value_c14n)?;
        unsigned = format!(
            r#"<xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp Id="{tid}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties>"#,
            b64(&token)
        );
    }
    Ok(assemble(&si, &value, &unsigned))
}

/// Signs `data` (the file `file_name`). Enveloped: returns the XML document with the signature
/// added; detached: returns the signature document.
pub fn sign(data: &[u8], file_name: &str, mode: Mode, signer: &SignerCert, sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>, timestamp: Option<Timestamper>) -> Result<Vec<u8>> {
    match mode {
        Mode::Detached => {
            let sig = build_signature(&uri_encode(file_name), false, &Sha256::digest(data), mime_type(file_name), signer, sign, timestamp)?;
            Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{sig}\n").into_bytes())
        }
        Mode::Enveloped => {
            let doc = xml::parse(data)?;
            let root = doc.root().ok_or_else(|| anyhow!("XML: no document element"))?;
            let digest = Sha256::digest(xml::canonicalize(&doc, 0, &C14n { exclusive: true, ..Default::default() }, None));
            let sig = build_signature("", true, &digest, "text/xml", signer, sign, timestamp)?;
            let node = &doc.nodes[root];
            let mut out = Vec::with_capacity(data.len() + sig.len() + 64);
            if node.end_tag == node.start {
                // <root .../> becomes <root ...>signature</root>.
                let tag_end = node.start + data[node.start..].iter().position(|&b| b == b'>').ok_or_else(|| anyhow!("XML: start tag"))?;
                if tag_end == 0 || data[tag_end - 1] != b'/' {
                    bail!("XML: unexpected empty element");
                }
                let qname: String = std::str::from_utf8(&data[node.start + 1..tag_end - 1])?.split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or_default().to_string();
                out.extend_from_slice(&data[..tag_end - 1]);
                out.push(b'>');
                out.extend_from_slice(sig.as_bytes());
                out.extend_from_slice(format!("</{qname}>").as_bytes());
                out.extend_from_slice(&data[tag_end + 1..]);
            } else {
                out.extend_from_slice(&data[..node.end_tag]);
                out.extend_from_slice(sig.as_bytes());
                out.extend_from_slice(&data[node.end_tag..]);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::KeyAlg;

    fn signer() -> SignerCert {
        SignerCert { der: vec![0x30, 0], issuer_der: vec![0x30, 0], serial_be: vec![1], chain: vec![vec![0x30, 0]], alg: KeyAlg::Rsa }
    }

    #[test]
    fn enveloped_signature_leaves_the_document_unchanged() {
        let input = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<inv:Invoice xmlns:inv=\"urn:x\" xmlns=\"urn:d\">\r\n  <Line no=\"1\">Кафе</Line>\r\n</inv:Invoice>\r\n";
        let got = std::cell::RefCell::new(Vec::new());
        let fake = |d: &[u8]| {
            *got.borrow_mut() = d.to_vec();
            Ok(vec![7u8; 256])
        };
        let out = sign(input.as_bytes(), "invoice.xml", Mode::Enveloped, &signer(), &fake, None).unwrap();
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<inv:Invoice"));
        assert!(text.ends_with("</ds:Signature></inv:Invoice>\r\n"));
        // Removing the signature gives the same canonical document.
        let doc = xml::parse(&out).unwrap();
        let sig = doc.descendants(0).into_iter().find(|&n| doc.is(n, NS_DS, "Signature")).unwrap();
        let exc = C14n { exclusive: true, ..Default::default() };
        assert_eq!(xml::canonicalize(&doc, 0, &exc, Some(sig)), xml::canonicalize(&xml::parse(input.as_bytes()).unwrap(), 0, &exc, None));
        // What was signed is the canonical SignedInfo, with the namespace on it.
        let si = String::from_utf8(got.borrow().clone()).unwrap();
        assert!(si.starts_with(&format!("<ds:SignedInfo xmlns:ds=\"{NS_DS}\">")), "{si}");
    }

    /// With a real certificate (DOC_SIGNER_THUMB, Windows store / Linux folder): signs
    /// `DOC_SIGNER_TEST_XML` (or a generated sample in the temp folder) as `<file>.signed.xml`
    /// (enveloped) and `<file>.xades.xml` (detached) and verifies both. Optional DOC_SIGNER_TSA.
    #[test]
    #[ignore]
    fn xades_with_real_certificate() {
        let Ok(thumb_hex) = std::env::var("DOC_SIGNER_THUMB") else {
            eprintln!("SKIPPED xades_with_real_certificate: set DOC_SIGNER_THUMB");
            return;
        };
        let input = std::env::var("DOC_SIGNER_TEST_XML").unwrap_or_else(|_| {
            let p = std::env::temp_dir().join("doc-signer-sample.xml");
            std::fs::write(&p, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Invoice xmlns=\"urn:example:invoice\" xmlns:cbc=\"urn:example:basic\">\n  <cbc:ID>2026-001</cbc:ID>\n  <cbc:Note>Тест &amp; проверка</cbc:Note>\n</Invoice>\n").unwrap();
            p.display().to_string()
        });
        let thumb: Vec<u8> = (0..thumb_hex.len()).step_by(2).map(|i| u8::from_str_radix(&thumb_hex[i..i + 2], 16).unwrap()).collect();
        let signer = crate::certs::load_signer(&thumb).unwrap();
        let tsa = std::env::var("DOC_SIGNER_TSA").ok();
        let ts = |v: &[u8]| crate::tsa::timestamp(tsa.as_deref().unwrap(), v).map(|t| t.token);
        let ts_ref: Option<Timestamper> = if tsa.is_some() { Some(&ts) } else { None };
        let data = std::fs::read(&input).unwrap();
        let name = std::path::Path::new(&input).file_name().unwrap().to_string_lossy().into_owned();
        for (mode, out) in [(Mode::Enveloped, format!("{input}.signed.xml")), (Mode::Detached, format!("{input}.xades.xml"))] {
            let signed = sign(&data, &name, mode, &signer, &|d| crate::certs::sign_data(&thumb, d, signer.alg), ts_ref).unwrap();
            std::fs::write(&out, signed).unwrap();
            for r in crate::verify::verify_file(std::path::Path::new(&out), None).unwrap() {
                eprintln!("verify {out} [{}]", r.level);
                for l in &r.checks {
                    eprintln!("  {:?} {}", l.status, l.text);
                }
                assert!(r.checks.iter().all(|l| l.status != crate::verify::Status::Fail), "{:?}", r.checks);
                assert_eq!(r.checks[0].status, crate::verify::Status::Ok);
            }
        }
    }

    #[test]
    fn empty_root_and_detached() {
        let fake = |_: &[u8]| Ok(vec![7u8; 64]);
        let out = sign(b"<a x='1' />", "a.xml", Mode::Enveloped, &signer(), &fake, None).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("<a x='1' ><ds:Signature") && text.ends_with("</ds:Signature></a>"), "{text}");
        let det = String::from_utf8(sign(b"anything", "my file.pdf", Mode::Detached, &signer(), &fake, None).unwrap()).unwrap();
        assert!(det.contains("URI=\"my%20file.pdf\"") && det.contains("<xades:MimeType>application/pdf</xades:MimeType>"));
    }
}
