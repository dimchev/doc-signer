//! ASiC-E containers with a CAdES signature (ETSI EN 319 162-1): one `.asice` ZIP holding the
//! signed files, `META-INF/ASiCManifest.xml` (SHA-256 of every file) and
//! `META-INF/signature001.p7s` (detached CAdES over the manifest).

use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use base64::Engine;
use chrono::{Datelike, Local, Timelike};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use sha2::{Digest, Sha256};

use crate::cades;
use crate::cms::SignerCert;
use crate::pdf::Timestamper;

pub const MIMETYPE: &str = "application/vnd.etsi.asic-e+zip";
pub const SIGNATURE: &str = "META-INF/signature001.p7s";
pub const MANIFEST: &str = "META-INF/ASiCManifest.xml";

/// Builds the container from `(name inside the container, content)` pairs.
pub fn build(files: &[(String, Vec<u8>)], signer: &SignerCert, sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>, timestamp: Option<Timestamper>) -> Result<Vec<u8>> {
    if files.is_empty() {
        bail!("no files for the container");
    }
    let manifest = manifest(files);
    let signature = cades::sign(manifest.as_bytes(), cades::Format::Detached, signer, sign, timestamp)?;
    let mut zip = ZipWriter::default();
    zip.add("mimetype", MIMETYPE.as_bytes(), false)?;
    for (name, data) in files {
        zip.add(name, data, true)?;
    }
    zip.add(MANIFEST, manifest.as_bytes(), true)?;
    zip.add(SIGNATURE, &signature, false)?;
    zip.finish()
}

/// Unique file names for the container root: `a.txt`, `a (2).txt`, ...
pub fn entry_names(paths: &[&Path]) -> Vec<String> {
    let mut used: Vec<String> = Vec::new();
    for p in paths {
        let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let (stem, ext) = match name.rfind('.') {
            Some(i) if i > 0 => (&name[..i], &name[i..]),
            _ => (name.as_str(), ""),
        };
        let mut candidate = name.clone();
        let mut n = 2;
        while used.iter().any(|u| u.eq_ignore_ascii_case(&candidate)) || candidate.eq_ignore_ascii_case("mimetype") {
            candidate = format!("{stem} ({n}){ext}");
            n += 1;
        }
        used.push(candidate);
    }
    used
}

fn manifest(files: &[(String, Vec<u8>)]) -> String {
    let mut x = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    x += "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n";
    x += &format!("  <asic:SigReference URI=\"{SIGNATURE}\" MimeType=\"application/pkcs7-signature\"/>\n");
    for (name, data) in files {
        let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(data));
        x += &format!("  <asic:DataObjectReference URI=\"{}\" MimeType=\"{}\">\n", xml_escape(&uri_encode(name)), mime_type(name));
        x += "    <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n";
        x += &format!("    <ds:DigestValue>{digest}</ds:DigestValue>\n");
        x += "  </asic:DataObjectReference>\n";
    }
    x += "</asic:ASiCManifest>\n";
    x
}

fn uri_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out += &format!("%{b:02X}");
        }
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn mime_type(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or_default().to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "xml" => "application/xml",
        "json" => "application/json",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "tif" | "tiff" => "image/tiff",
        "zip" => "application/zip",
        "doc" => "application/msword",
        "xls" => "application/vnd.ms-excel",
        "ppt" => "application/vnd.ms-powerpoint",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "p7s" => "application/pkcs7-signature",
        "p7m" => "application/pkcs7-mime",
        _ => "application/octet-stream",
    }
}

/// Minimal ZIP writer (no ZIP64): stored or deflated entries, UTF-8 names.
#[derive(Default)]
struct ZipWriter {
    out: Vec<u8>,
    central: Vec<u8>,
    count: u16,
}

impl ZipWriter {
    fn add(&mut self, name: &str, data: &[u8], compress: bool) -> Result<()> {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let crc = crc.sum();
        let (method, body) = if compress {
            let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
            e.write_all(data)?;
            let z = e.finish()?;
            if z.len() < data.len() { (8u16, z) } else { (0u16, data.to_vec()) }
        } else {
            (0u16, data.to_vec())
        };
        let offset = self.out.len();
        if data.len() > u32::MAX as usize || offset + body.len() > u32::MAX as usize || self.count == u16::MAX {
            bail!("the container would exceed 4 GB / 65535 files");
        }
        let now = Local::now();
        let dos_time = ((now.hour() << 11) | (now.minute() << 5) | (now.second() / 2)) as u16;
        let dos_date = (((now.year().max(1980) - 1980) as u32) << 9 | now.month() << 5 | now.day()) as u16;
        let flags: u16 = if name.is_ascii() { 0 } else { 1 << 11 };
        let fields = |v: &mut Vec<u8>| {
            v.extend_from_slice(&20u16.to_le_bytes());
            v.extend_from_slice(&flags.to_le_bytes());
            v.extend_from_slice(&method.to_le_bytes());
            v.extend_from_slice(&dos_time.to_le_bytes());
            v.extend_from_slice(&dos_date.to_le_bytes());
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&(body.len() as u32).to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
        };
        self.out.extend_from_slice(&0x04034b50u32.to_le_bytes());
        fields(&mut self.out);
        self.out.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(&body);

        self.central.extend_from_slice(&0x02014b50u32.to_le_bytes());
        self.central.extend_from_slice(&20u16.to_le_bytes());
        fields(&mut self.central);
        // comment length, disk number, internal and external attributes
        self.central.extend_from_slice(&[0; 10]);
        self.central.extend_from_slice(&(offset as u32).to_le_bytes());
        self.central.extend_from_slice(name.as_bytes());
        self.count += 1;
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        let cd_offset = self.out.len();
        if cd_offset + self.central.len() > u32::MAX as usize {
            bail!("the container would exceed 4 GB");
        }
        self.out.extend_from_slice(&self.central);
        self.out.extend_from_slice(&0x06054b50u32.to_le_bytes());
        self.out.extend_from_slice(&[0; 4]);
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&(self.central.len() as u32).to_le_bytes());
        self.out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes());
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::KeyAlg;
    use std::io::Read;

    fn signer() -> SignerCert {
        SignerCert { der: vec![0x30, 0], issuer_der: vec![0x30, 0], serial_be: vec![1], chain: vec![vec![0x30, 0]], alg: KeyAlg::Rsa }
    }

    fn u16le(b: &[u8], at: usize) -> usize {
        u16::from_le_bytes([b[at], b[at + 1]]) as usize
    }

    fn u32le(b: &[u8], at: usize) -> usize {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
    }

    /// Reads every entry back through the central directory.
    fn entries(zip: &[u8]) -> Vec<(String, Vec<u8>)> {
        let eocd = zip.len() - 22;
        assert_eq!(u32le(zip, eocd), 0x06054b50);
        let (count, mut p) = (u16le(zip, eocd + 10), u32le(zip, eocd + 16));
        let mut out = Vec::new();
        for _ in 0..count {
            assert_eq!(u32le(zip, p), 0x02014b50);
            let (method, csize, nlen, off) = (u16le(zip, p + 10), u32le(zip, p + 20), u16le(zip, p + 28), u32le(zip, p + 42));
            let name = String::from_utf8(zip[p + 46..p + 46 + nlen].to_vec()).unwrap();
            let start = off + 30 + u16le(zip, off + 26) + u16le(zip, off + 28);
            let raw = &zip[start..start + csize];
            let data = if method == 8 {
                let mut v = Vec::new();
                flate2::read::DeflateDecoder::new(raw).read_to_end(&mut v).unwrap();
                v
            } else {
                raw.to_vec()
            };
            let mut crc = flate2::Crc::new();
            crc.update(&data);
            assert_eq!(crc.sum() as usize, u32le(zip, p + 16), "crc of {name}");
            out.push((name, data));
            p += 46 + nlen;
        }
        out
    }

    #[test]
    fn container_layout_follows_asic_e() {
        let files = vec![("report.docx".to_string(), vec![7u8; 5000]), ("бележки и данни.txt".to_string(), b"hello".to_vec())];
        let fake = |_: &[u8]| Ok(vec![0xAB; 256]);
        let zip = build(&files, &signer(), &fake, None).unwrap();
        // `mimetype` first, stored, no extra field, so readers can sniff the type at offset 38.
        assert_eq!(&zip[30..38], b"mimetype");
        assert_eq!(u16le(&zip, 8), 0);
        assert_eq!(u16le(&zip, 28), 0);
        assert_eq!(&zip[38..38 + MIMETYPE.len()], MIMETYPE.as_bytes());

        let e = entries(&zip);
        let names: Vec<&str> = e.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["mimetype", "report.docx", "бележки и данни.txt", MANIFEST, SIGNATURE]);
        assert_eq!(e[1].1, files[0].1);
        let manifest = String::from_utf8(e[3].1.clone()).unwrap();
        let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&files[0].1));
        assert!(manifest.contains(&format!("<ds:DigestValue>{digest}</ds:DigestValue>")));
        assert!(manifest.contains("URI=\"%D0%B1"), "non-ASCII names are percent-encoded: {manifest}");
        assert!(manifest.contains("wordprocessingml.document"));
    }

    #[test]
    fn entry_names_are_unique() {
        let paths = [Path::new("a/x.txt"), Path::new("b/x.txt"), Path::new("c/X.TXT"), Path::new("mimetype")];
        assert_eq!(entry_names(&paths), ["x.txt", "x (2).txt", "X (3).TXT", "mimetype (2)"]);
    }

    /// End-to-end with a real certificate: packs `DOC_SIGNER_TEST_PDF` (any file) into
    /// `<file>.asice` next to it. Optional `DOC_SIGNER_TSA` adds a time-stamp.
    #[test]
    #[ignore]
    fn asice_with_real_certificate() {
        let (Ok(input), Ok(thumb_hex)) = (std::env::var("DOC_SIGNER_TEST_PDF"), std::env::var("DOC_SIGNER_THUMB")) else {
            eprintln!("SKIPPED asice_with_real_certificate: set DOC_SIGNER_TEST_PDF and DOC_SIGNER_THUMB to run it");
            return;
        };
        let thumb: Vec<u8> = (0..thumb_hex.len()).step_by(2).map(|i| u8::from_str_radix(&thumb_hex[i..i + 2], 16).unwrap()).collect();
        let signer = crate::certs::load_signer(&thumb).unwrap();
        let path = Path::new(&input);
        let files = vec![(entry_names(&[path]).remove(0), std::fs::read(path).unwrap())];
        let tsa = std::env::var("DOC_SIGNER_TSA").ok();
        let ts = |v: &[u8]| crate::tsa::timestamp(tsa.as_deref().unwrap(), v).map(|t| t.token);
        let ts_ref: Option<Timestamper> = if tsa.is_some() { Some(&ts) } else { None };
        let zip = build(&files, &signer, &|d| crate::certs::sign_data(&thumb, d, signer.alg), ts_ref).unwrap();
        std::fs::write(format!("{input}.asice"), zip).unwrap();
    }
}
