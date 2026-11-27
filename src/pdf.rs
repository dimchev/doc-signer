//! PDF inspection and PAdES signing via an incremental update (existing content and
//! earlier signatures are never rewritten).

use std::collections::{BTreeSet, HashMap};
use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Local};
use lopdf::{Dictionary, Document, LoadOptions, Object, ObjectId, Permissions, Stream};
use sha2::{Digest, Sha256};

use crate::cms::{self, SignerCert};
use crate::i18n::t;
use crate::stamp;

#[derive(Clone, Copy, Debug)]
pub struct PageGeom {
    /// CropBox in user space: x0, y0, x1, y1.
    pub crop: [f32; 4],
    /// Normalized /Rotate: 0, 90, 180 or 270 (clockwise).
    pub rotate: i32,
}

impl PageGeom {
    fn wh(&self) -> (f32, f32) {
        (self.crop[2] - self.crop[0], self.crop[3] - self.crop[1])
    }

    /// Size of the page as displayed (after rotation), in points.
    pub fn display_size(&self) -> (f32, f32) {
        let (w, h) = self.wh();
        if self.rotate % 180 == 0 { (w, h) } else { (h, w) }
    }

    /// Display point (origin top-left, y down) -> user space point.
    fn to_user(&self, dx: f32, dy: f32) -> (f32, f32) {
        let (w, h) = self.wh();
        let (u, v) = match self.rotate {
            90 => (dy, dx),
            180 => (w - dx, dy),
            270 => (w - dy, h - dx),
            _ => (dx, h - dy),
        };
        (self.crop[0] + u, self.crop[1] + v)
    }

    /// Display rect (x, y, w, h; top-left origin) -> user space rect [x0 y0 x1 y1].
    pub fn display_rect_to_user(&self, r: [f32; 4]) -> [f32; 4] {
        let (ax, ay) = self.to_user(r[0], r[1]);
        let (bx, by) = self.to_user(r[0] + r[2], r[1] + r[3]);
        [ax.min(bx), ay.min(by), ax.max(bx), ay.max(by)]
    }

    /// Appearance /Matrix that keeps the stamp upright on rotated pages.
    fn appearance_matrix(&self) -> [i32; 6] {
        match self.rotate {
            90 => [0, 1, -1, 0, 0, 0],
            180 => [-1, 0, 0, -1, 0, 0],
            270 => [0, -1, 1, 0, 0, 0],
            _ => [1, 0, 0, 1, 0, 0],
        }
    }
}

#[derive(Clone, Debug)]
pub struct PdfInfo {
    pub pages: Vec<PageGeom>,
    pub signatures: usize,
    /// Encrypted (opened with an empty or the given password).
    pub encrypted: bool,
}

fn inherited<'a>(doc: &'a Document, mut id: ObjectId, key: &[u8]) -> Option<&'a Object> {
    for _ in 0..64 {
        let dict = doc.get_dictionary(id).ok()?;
        if let Ok(v) = dict.get(key) {
            return doc.dereference(v).ok().map(|(_, o)| o);
        }
        id = dict.get(b"Parent").ok()?.as_reference().ok()?;
    }
    None
}

fn rect_of(doc: &Document, o: &Object) -> Option<[f32; 4]> {
    let arr = o.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let mut r = [0f32; 4];
    for (i, v) in arr.iter().enumerate() {
        let v = doc.dereference(v).ok()?.1;
        r[i] = v.as_float().ok()?;
    }
    Some([r[0].min(r[2]), r[1].min(r[3]), r[0].max(r[2]), r[1].max(r[3])])
}

fn page_geoms(doc: &Document) -> Vec<(ObjectId, PageGeom)> {
    doc.get_pages()
        .values()
        .map(|&id| {
            let media = inherited(doc, id, b"MediaBox").and_then(|o| rect_of(doc, o)).unwrap_or([0.0, 0.0, 595.0, 842.0]);
            let crop = inherited(doc, id, b"CropBox").and_then(|o| rect_of(doc, o)).unwrap_or(media);
            let rot = inherited(doc, id, b"Rotate").and_then(|o| o.as_i64().ok()).unwrap_or(0);
            (id, PageGeom { crop, rotate: (((rot % 360) + 360) % 360) as i32 / 90 * 90 })
        })
        .collect()
}

fn is_sig_field(d: &Dictionary) -> bool {
    matches!(d.get(b"FT").and_then(|o| o.as_name()), Ok(n) if n == b"Sig")
}

fn sig_fields(doc: &Document) -> impl Iterator<Item = &Dictionary> {
    doc.objects.values().filter_map(|o| o.as_dict().ok()).filter(|d| is_sig_field(d))
}

/// Why an encrypted PDF cannot be opened or signed; the UI answers it with a password prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locked {
    /// A user (open) password is set and none or an empty one was given.
    NeedsPassword,
    WrongPassword,
    /// Opened, but the permissions forbid signing; the owner password lifts that.
    SigningNotAllowed,
}

impl std::fmt::Display for Locked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Locked::NeedsPassword => t().err_pdf_password,
            Locked::WrongPassword => t().err_wrong_password,
            Locked::SigningNotAllowed => t().err_no_sign_permission,
        })
    }
}

impl std::error::Error for Locked {}

/// Loads (and, for encrypted files, decrypts) a PDF. Owner-password-only files open without a password.
fn load(bytes: &[u8], password: Option<&str>) -> Result<Document> {
    let options = password.map(LoadOptions::with_password).unwrap_or_default();
    let doc = match Document::load_mem_with_options(bytes, options) {
        Ok(doc) => doc,
        Err(lopdf::Error::InvalidPassword) => return Err(Locked::WrongPassword.into()),
        Err(e) => bail!("{}: {e}", t().err_invalid_pdf),
    };
    // lopdf leaves /Encrypt in the trailer only when it could not decrypt.
    if doc.trailer.get(b"Encrypt").is_ok() {
        return Err(Locked::NeedsPassword.into());
    }
    Ok(doc)
}

/// Signing adds a signature field: allowed with "annotate / fill in forms" (R3+: "fill in forms"
/// alone is enough, as in Adobe's "Signing: Allowed"), or always with the owner password.
fn check_can_sign(doc: &Document, password: Option<&str>) -> Result<()> {
    let Some(state) = &doc.encryption_state else { return Ok(()) };
    let p = state.permissions();
    if p.contains(Permissions::ANNOTABLE) || (state.revision() >= 3 && p.contains(Permissions::FILLABLE)) {
        return Ok(());
    }
    if let (Some(pw), Ok(enc)) = (password, state.encode()) {
        // A document holding only /Encrypt and /ID is enough for lopdf's password checks.
        let mut probe = Document::with_version("1.7");
        let enc_id = probe.add_object(enc);
        probe.trailer.set("Encrypt", Object::Reference(enc_id));
        if let Ok(id) = doc.trailer.get(b"ID") {
            probe.trailer.set("ID", id.clone());
        }
        if probe.authenticate_owner_password(pw).is_ok() {
            return Ok(());
        }
        if probe.authenticate_user_password(pw).is_err() {
            return Err(Locked::WrongPassword.into());
        }
    }
    Err(Locked::SigningNotAllowed.into())
}

/// Visible appearance of an existing signature, as a standalone one-page PDF.
pub struct Appearance {
    pub page: usize,
    pub signer: String,
    /// Width and height in points.
    pub size: (f32, f32),
    /// One page of exactly `size`, containing only the appearance (no page content underneath).
    pub pdf: Vec<u8>,
}

/// PDF text string: UTF-16BE with BOM, otherwise PDFDocEncoding (≈ Latin-1).
fn pdf_text(b: &[u8]) -> String {
    if let Some(rest) = b.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        b.iter().map(|&c| c as char).collect()
    }
}

fn copy_dict(src: &Document, dst: &mut Document, d: Dictionary, map: &mut HashMap<ObjectId, ObjectId>) -> Result<Dictionary> {
    let mut out = Dictionary::new();
    for (k, v) in d.into_iter() {
        // Back-links to the page / field tree would drag the whole document along.
        if k == b"Parent" || k == b"P" {
            continue;
        }
        out.set(k, copy_obj(src, dst, v, map)?);
    }
    Ok(out)
}

fn copy_obj(src: &Document, dst: &mut Document, obj: Object, map: &mut HashMap<ObjectId, ObjectId>) -> Result<Object> {
    Ok(match obj {
        Object::Reference(r) => Object::Reference(copy_ref(src, dst, r, map)?),
        Object::Array(a) => Object::Array(a.into_iter().map(|o| copy_obj(src, dst, o, map)).collect::<Result<_>>()?),
        Object::Dictionary(d) => Object::Dictionary(copy_dict(src, dst, d, map)?),
        Object::Stream(mut s) => {
            s.dict = copy_dict(src, dst, s.dict, map)?;
            Object::Stream(s)
        }
        o => o,
    })
}

fn copy_ref(src: &Document, dst: &mut Document, id: ObjectId, map: &mut HashMap<ObjectId, ObjectId>) -> Result<ObjectId> {
    if let Some(n) = map.get(&id) {
        return Ok(*n);
    }
    let new = dst.new_object_id();
    map.insert(id, new);
    let obj = src.get_object(id).map(Object::clone).unwrap_or(Object::Null);
    let copied = copy_obj(src, dst, obj, map)?;
    dst.objects.insert(new, copied);
    Ok(new)
}

/// One-page PDF of `bbox`'s size that draws only the appearance form `ap` (upright, its /Matrix reset).
fn standalone_appearance(src: &Document, ap: ObjectId, bbox: [f32; 4]) -> Result<Vec<u8>> {
    let mut dst = Document::with_version("1.7");
    let mut map = HashMap::new();
    let form = copy_ref(src, &mut dst, ap, &mut map)?;
    if let Ok(Object::Stream(s)) = dst.get_object_mut(form) {
        s.dict.set("Matrix", Object::Array([1, 0, 0, 1, 0, 0].into_iter().map(Object::Integer).collect()));
    }
    let (w, h) = (bbox[2] - bbox[0], bbox[3] - bbox[1]);
    let content = format!("q 1 0 0 1 {} {} cm /Ap Do Q", -bbox[0], -bbox[1]);
    let content_id = dst.add_object(Stream::new(Dictionary::new(), content.into_bytes()));
    let pages_id = dst.new_object_id();
    let mut xobjects = Dictionary::new();
    xobjects.set("Ap", Object::Reference(form));
    let mut resources = Dictionary::new();
    resources.set("XObject", xobjects);
    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    page.set("Parent", Object::Reference(pages_id));
    page.set("MediaBox", Object::Array(vec![0.into(), 0.into(), Object::Real(w), Object::Real(h)]));
    page.set("Contents", Object::Reference(content_id));
    page.set("Resources", resources);
    let page_id = dst.add_object(page);
    let mut pages = Dictionary::new();
    pages.set("Type", Object::Name(b"Pages".to_vec()));
    pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
    pages.set("Count", 1i64);
    dst.objects.insert(pages_id, Object::Dictionary(pages));
    let mut catalog = Dictionary::new();
    catalog.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", Object::Reference(pages_id));
    let catalog_id = dst.add_object(catalog);
    dst.trailer.set("Root", Object::Reference(catalog_id));
    let mut out = Vec::new();
    dst.save_to(&mut out)?;
    Ok(out)
}

/// Visible appearances of all signatures in the document (widgets with `/FT /Sig`, directly or
/// through their parent field, that have a normal appearance stream).
pub fn signature_appearances(bytes: &[u8]) -> Result<Vec<Appearance>> {
    let doc = load(bytes, None)?;
    let pages: Vec<ObjectId> = doc.get_pages().values().copied().collect();
    let mut out = Vec::new();
    for obj in doc.objects.values() {
        let Ok(widget) = obj.as_dict() else { continue };
        if !matches!(widget.get(b"Subtype").and_then(|o| o.as_name()), Ok(n) if n == b"Widget") {
            continue;
        }
        let parent = widget.get(b"Parent").ok().and_then(|p| p.as_reference().ok()).and_then(|p| doc.get_dictionary(p).ok());
        let field = if is_sig_field(widget) { widget } else if let Some(p) = parent.filter(|p| is_sig_field(p)) { p } else { continue };
        let ap = widget.get(b"AP").ok().and_then(|ap| doc.dereference(ap).ok()).and_then(|(_, ap)| ap.as_dict().ok());
        let Some(ap_id) = ap.and_then(|ap| ap.get(b"N").ok()).and_then(|n| n.as_reference().ok()) else { continue };
        let Ok(stream) = doc.get_object(ap_id).and_then(|o| o.as_stream()) else { continue };
        let Some(bbox) = stream.dict.get(b"BBox").ok().and_then(|b| rect_of(&doc, b)) else { continue };
        let size = (bbox[2] - bbox[0], bbox[3] - bbox[1]);
        if size.0 < 1.0 || size.1 < 1.0 {
            continue;
        }
        let page = widget.get(b"P").ok().and_then(|p| p.as_reference().ok()).and_then(|p| pages.iter().position(|&x| x == p)).unwrap_or(0);
        let sig = field.get(b"V").ok().and_then(|v| doc.dereference(v).ok()).and_then(|(_, v)| v.as_dict().ok());
        let name = sig.and_then(|s| s.get(b"Name").ok()).or_else(|| field.get(b"T").ok());
        let signer = name.and_then(|n| n.as_str().ok()).map(pdf_text).unwrap_or_default();
        out.push(Appearance { page, signer, size, pdf: standalone_appearance(&doc, ap_id, bbox)? });
    }
    out.sort_by_key(|a| a.page);
    Ok(out)
}

pub fn inspect(bytes: &[u8], password: Option<&str>) -> Result<PdfInfo> {
    let doc = load(bytes, password)?;
    check_can_sign(&doc, password)?;
    let pages: Vec<PageGeom> = page_geoms(&doc).into_iter().map(|(_, g)| g).collect();
    if pages.is_empty() {
        bail!(t().err_no_pages);
    }
    let signatures = sig_fields(&doc).filter(|d| d.get(b"V").is_ok()).count();
    Ok(PdfInfo { pages, signatures, encrypted: doc.encryption_state.is_some() })
}

pub struct Visible {
    pub page: usize,
    /// x, y, w, h in display points, origin top-left.
    pub rect: [f32; 4],
    /// The stamp image, stretched over `rect`.
    pub image: stamp::Rendered,
}

pub struct SignRequest {
    pub signer_name: String,
    pub reason: String,
    pub location: String,
    pub contact: String,
    pub time: DateTime<Local>,
    pub visible: Option<Visible>,
    /// Password of an encrypted PDF (user or owner); `None` if it opens without one.
    pub password: Option<String>,
}

// ---------- serialization ----------

fn write_name(out: &mut Vec<u8>, n: &[u8]) {
    out.push(b'/');
    for &c in n {
        if (0x21..=0x7e).contains(&c) && !b"()<>[]{}/%#".contains(&c) {
            out.push(c);
        } else {
            write!(out, "#{c:02X}").unwrap();
        }
    }
}

fn write_hex(out: &mut Vec<u8>, b: &[u8]) {
    out.push(b'<');
    for c in b {
        write!(out, "{c:02X}").unwrap();
    }
    out.push(b'>');
}

fn write_obj(out: &mut Vec<u8>, o: &Object) {
    match o {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => write!(out, "{b}").unwrap(),
        Object::Integer(i) => write!(out, "{i}").unwrap(),
        Object::Real(r) => write!(out, "{r}").unwrap(),
        Object::Name(n) => write_name(out, n),
        Object::String(s, _) => write_hex(out, s),
        Object::Array(a) => {
            out.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_obj(out, v);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => write_dict(out, d),
        Object::Stream(s) => {
            let mut d = s.dict.clone();
            d.set("Length", s.content.len() as i64);
            write_dict(out, &d);
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(&s.content);
            out.extend_from_slice(b"\nendstream");
        }
        Object::Reference((id, g)) => write!(out, "{id} {g} R").unwrap(),
    }
}

fn write_dict(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend_from_slice(b"<<");
    for (k, v) in d.iter() {
        write_name(out, k);
        out.push(b' ');
        write_obj(out, v);
    }
    out.extend_from_slice(b">>");
}

fn obj_bytes(o: &Object) -> Vec<u8> {
    let mut v = Vec::new();
    write_obj(&mut v, o);
    v
}

/// PDF text string as UTF-16BE with BOM.
fn text(s: &str) -> Object {
    let mut b = vec![0xFE, 0xFF];
    for u in s.encode_utf16() {
        b.extend_from_slice(&u.to_be_bytes());
    }
    Object::String(b, lopdf::StringFormat::Hexadecimal)
}

fn stream(dict: Dictionary, data: &[u8], compress: bool) -> Object {
    let mut d = dict;
    let content = if compress {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(data).unwrap();
        d.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        e.finish().unwrap()
    } else {
        data.to_vec()
    };
    Object::Stream(Stream::new(d, content))
}

fn stream_obj(dict: Dictionary, data: &[u8], compress: bool) -> Vec<u8> {
    let mut d = dict;
    let content = if compress {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(data).unwrap();
        d.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        e.finish().unwrap()
    } else {
        data.to_vec()
    };
    d.set("Length", content.len() as i64);
    let mut out = Vec::new();
    write_dict(&mut out, &d);
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(&content);
    out.extend_from_slice(b"\nendstream");
    out
}

fn startxref(bytes: &[u8]) -> Result<usize> {
    let tail_start = bytes.len().saturating_sub(2048);
    let tail = &bytes[tail_start..];
    let pos = tail.windows(9).rposition(|w| w == b"startxref").with_context(|| format!("{}: startxref", t().err_pdf_structure))?;
    let digits: String = tail[pos + 9..]
        .iter()
        .skip_while(|c| c.is_ascii_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .map(|&c| c as char)
        .collect();
    digits.parse().with_context(|| format!("{}: startxref", t().err_pdf_structure))
}

fn resolve_array(doc: &Document, o: Option<&Object>) -> Vec<Object> {
    o.and_then(|o| doc.dereference(o).ok())
        .and_then(|(_, o)| o.as_array().ok().cloned())
        .unwrap_or_default()
}

// ---------- signing ----------

/// Returns the RFC 3161 time-stamp token for the given signature value.
pub type Timestamper<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>>;

/// What goes into the new signature field.
enum Kind<'a> {
    /// PAdES signature (`ETSI.CAdES.detached`), optionally with a signature time-stamp.
    Signature { req: &'a SignRequest, signer: &'a SignerCert, sign: &'a dyn Fn(&[u8]) -> Result<Vec<u8>>, timestamp: Option<Timestamper<'a>> },
    /// Document time-stamp (`ETSI.RFC3161`, PAdES B-LTA): `tsa` returns the token for a SHA-256 digest.
    DocTimeStamp { tsa: Timestamper<'a> },
}

pub fn sign_pdf(input: &[u8], req: &SignRequest, signer: &SignerCert, sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>, timestamp: Option<Timestamper>) -> Result<Vec<u8>> {
    add_signature(input, req.password.as_deref(), Kind::Signature { req, signer, sign, timestamp })
}

/// Adds an invisible document time-stamp over the whole file (PAdES B-LTA).
pub fn add_doc_timestamp(input: &[u8], password: Option<&str>, tsa: Timestamper) -> Result<Vec<u8>> {
    add_signature(input, password, Kind::DocTimeStamp { tsa })
}

/// CMS (DER, padding removed) of the signature or document time-stamp that covers the most bytes,
/// i.e. the newest one.
pub fn last_signature_cms(bytes: &[u8], password: Option<&str>) -> Result<Vec<u8>> {
    let doc = load(bytes, password)?;
    let covered = |d: &Dictionary| resolve_array(&doc, d.get(b"ByteRange").ok()).get(2).and_then(|o| o.as_i64().ok()).unwrap_or(0);
    let sig = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .filter(|d| d.get(b"ByteRange").is_ok() && d.get(b"Contents").is_ok())
        .max_by_key(|d| covered(d))
        .ok_or_else(|| anyhow!("{}: /Sig", t().err_pdf_structure))?;
    let contents = sig.get(b"Contents").and_then(|o| o.as_str()).map_err(|_| anyhow!("{}: /Contents", t().err_pdf_structure))?;
    cms::tlv_bytes(contents).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{}: /Contents", t().err_pdf_structure))
}

/// Adds validation data to the document security store (/DSS in the catalog) as an incremental
/// update, merging an existing /DSS (PAdES B-LT).
pub fn add_dss(input: &[u8], password: Option<&str>, certs: &[Vec<u8>], ocsps: &[Vec<u8>], crls: &[Vec<u8>]) -> Result<Vec<u8>> {
    let doc = load(input, password)?;
    let crypt = doc.encryption_state.as_ref();
    let root_id = doc.trailer.get(b"Root").and_then(|o| o.as_reference()).map_err(|_| anyhow!("{}: /Root", t().err_pdf_structure))?;
    let mut catalog = doc.get_dictionary(root_id).map_err(|_| anyhow!("{}: /Catalog", t().err_pdf_structure))?.clone();
    let existing = catalog.get(b"DSS").ok().and_then(|o| doc.dereference(o).ok()).and_then(|(_, o)| o.as_dict().ok().cloned()).unwrap_or_default();
    let mut next_id = first_id(&doc);
    let mut objects = Vec::new();
    let mut dss = Dictionary::new();
    for (key, items) in [("Certs", certs), ("OCSPs", ocsps), ("CRLs", crls)] {
        let mut refs = resolve_array(&doc, existing.get(key.as_bytes()).ok());
        for data in items {
            let id = (next_id, 0);
            next_id += 1;
            objects.push((id, seal(crypt, id, stream(Dictionary::new(), data, true))?));
            refs.push(Object::Reference(id));
        }
        if !refs.is_empty() {
            dss.set(key, refs);
        }
    }
    let dss_id = (next_id, 0);
    next_id += 1;
    objects.push((dss_id, seal(crypt, dss_id, Object::Dictionary(dss))?));
    catalog.set("DSS", Object::Reference(dss_id));
    objects.push((root_id, seal(crypt, root_id, Object::Dictionary(catalog))?));
    let encrypt = encrypt_ref(crypt, &mut next_id, &mut objects)?;
    Ok(write_update(input, &doc, &objects, &mut next_id, encrypt)?.0)
}

/// Encrypts `o` with the key of object `id` when the document is encrypted, then serializes it.
fn seal(crypt: Option<&lopdf::EncryptionState>, id: ObjectId, mut o: Object) -> Result<Vec<u8>> {
    if let Some(state) = crypt {
        lopdf::encryption::encrypt_object(state, id, &mut o).map_err(|e| anyhow!("{}: {e}", t().err_pdf_structure))?;
    }
    Ok(obj_bytes(&o))
}

/// The /Encrypt reference for the new trailer: the existing object, or a direct dictionary (rare)
/// written as a new indirect object.
fn encrypt_ref(crypt: Option<&lopdf::EncryptionState>, next_id: &mut u32, objects: &mut Vec<(ObjectId, Vec<u8>)>) -> Result<Option<ObjectId>> {
    let Some(state) = crypt else { return Ok(None) };
    if let Some(id) = state.encrypt_object_id() {
        return Ok(Some(id));
    }
    let id = (*next_id, 0);
    *next_id += 1;
    let dict = state.encode().map_err(|e| anyhow!("{}: /Encrypt: {e}", t().err_pdf_structure))?;
    objects.push((id, obj_bytes(&Object::Dictionary(dict))));
    Ok(Some(id))
}

/// Appends `objects` as an incremental update, with an xref table or stream like the previous
/// section. Returns the new file and the offset of every object's body (after `N G obj`).
fn write_update(input: &[u8], doc: &Document, objects: &[(ObjectId, Vec<u8>)], next_id: &mut u32, encrypt: Option<ObjectId>) -> Result<(Vec<u8>, HashMap<ObjectId, usize>)> {
    let prev_xref = startxref(input)?;
    let prev_is_stream = !input[prev_xref..].iter().skip_while(|c| c.is_ascii_whitespace()).take(4).eq(b"xref".iter());
    let root_id = doc.trailer.get(b"Root").and_then(|o| o.as_reference()).map_err(|_| anyhow!("{}: /Root", t().err_pdf_structure))?;

    let mut out = input.to_vec();
    if !matches!(out.last(), Some(b'\n') | Some(b'\r')) {
        out.push(b'\n');
    }
    let mut offsets: Vec<(ObjectId, usize)> = Vec::new();
    let mut bodies = HashMap::new();
    for (id, body) in objects {
        offsets.push((*id, out.len()));
        write!(out, "{} {} obj\n", id.0, id.1).unwrap();
        bodies.insert(*id, out.len());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }

    let mut trailer = Dictionary::new();
    trailer.set("Root", Object::Reference(root_id));
    for key in [&b"Info"[..], b"ID"] {
        if let Ok(v) = doc.trailer.get(key) {
            trailer.set(key.to_vec(), v.clone());
        }
    }
    trailer.set("Prev", prev_xref as i64);
    if let Some(id) = encrypt {
        trailer.set("Encrypt", Object::Reference(id));
    }

    let xref_off;
    if prev_is_stream {
        let xref_id = (*next_id, 0u16);
        *next_id += 1;
        xref_off = out.len();
        offsets.push((xref_id, xref_off));
        offsets.sort();
        let mut rows = Vec::new();
        let mut index = Vec::new();
        for (id, off) in &offsets {
            rows.push(1u8);
            rows.extend_from_slice(&(*off as u32).to_be_bytes());
            rows.extend_from_slice(&id.1.to_be_bytes());
            index.push(Object::Integer(id.0 as i64));
            index.push(Object::Integer(1));
        }
        trailer.set("Type", Object::Name(b"XRef".to_vec()));
        trailer.set("Size", *next_id as i64);
        trailer.set("W", Object::Array(vec![1.into(), 4.into(), 2.into()]));
        trailer.set("Index", index);
        write!(out, "{} 0 obj\n", xref_id.0).unwrap();
        out.extend(stream_obj(trailer, &rows, false));
        out.extend_from_slice(b"\nendobj\n");
    } else {
        xref_off = out.len();
        offsets.sort();
        out.extend_from_slice(b"xref\n");
        for (id, off) in &offsets {
            write!(out, "{} 1\n{:010} {:05} n\r\n", id.0, off, id.1).unwrap();
        }
        trailer.set("Size", *next_id as i64);
        out.extend_from_slice(b"trailer\n");
        write_dict(&mut out, &trailer);
        out.push(b'\n');
    }
    write!(out, "startxref\n{xref_off}\n%%EOF\n").unwrap();
    Ok((out, bodies))
}

fn first_id(doc: &Document) -> u32 {
    let trailer_size = doc.trailer.get(b"Size").and_then(|o| o.as_i64()).unwrap_or(0) as u32;
    trailer_size.max(doc.max_id + 1)
}

fn add_signature(input: &[u8], password: Option<&str>, kind: Kind) -> Result<Vec<u8>> {
    let doc = load(input, password)?;
    check_can_sign(&doc, password)?;
    // New and rewritten objects of an encrypted file are encrypted with their own object key
    // (ISO 32000-2, 7.6.2); the signature's /Contents and the xref stream stay plain.
    let crypt = doc.encryption_state.as_ref();
    let seal = |id: ObjectId, o: Object| seal(crypt, id, o);

    let root_id = doc.trailer.get(b"Root").and_then(|o| o.as_reference()).map_err(|_| anyhow!("{}: /Root", t().err_pdf_structure))?;
    let mut catalog = doc.get_dictionary(root_id).map_err(|_| anyhow!("{}: /Catalog", t().err_pdf_structure))?.clone();
    let mut next_id = first_id(&doc);
    let mut alloc = || {
        let id = (next_id, 0u16);
        next_id += 1;
        id
    };

    let pages = page_geoms(&doc);
    let mut objects: Vec<(ObjectId, Vec<u8>)> = Vec::new();

    // Unique field name.
    // Compare decoded names: /T is often UTF-16BE (ours is), so raw bytes would never match.
    let names: BTreeSet<String> = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .filter_map(|d| d.get(b"T").ok().and_then(|t| t.as_str().ok()).map(pdf_text))
        .collect();
    let field_name = (1..).map(|n| format!("Signature{n}")).find(|n| !names.contains(n)).unwrap();

    let sig_id = alloc();
    let widget_id = alloc();

    let visible = match &kind {
        Kind::Signature { req, .. } => req.visible.as_ref(),
        Kind::DocTimeStamp { .. } => None,
    };
    let page_idx = visible.map_or(0, |v| v.page.min(pages.len() - 1));
    let (page_id, geom) = pages[page_idx];

    let mut widget = Dictionary::new();
    widget.set("Type", Object::Name(b"Annot".to_vec()));
    widget.set("Subtype", Object::Name(b"Widget".to_vec()));
    widget.set("FT", Object::Name(b"Sig".to_vec()));
    widget.set("T", text(&field_name));
    widget.set("V", Object::Reference(sig_id));
    widget.set("F", 132i64);
    widget.set("P", Object::Reference(page_id));

    match visible {
        Some(v) => {
            let r = v.rect;
            let user = geom.display_rect_to_user(r);
            widget.set("Rect", Object::Array(user.iter().map(|&v| Object::Real(v)).collect()));

            let (w_pt, h_pt) = (r[2], r[3]);
            let img = &v.image;
            let (rgb, alpha) = img.rgb_and_alpha();

            let smask_id = alloc();
            let image_id = alloc();
            let form_id = alloc();

            let mut sm = Dictionary::new();
            sm.set("Type", Object::Name(b"XObject".to_vec()));
            sm.set("Subtype", Object::Name(b"Image".to_vec()));
            sm.set("Width", img.width as i64);
            sm.set("Height", img.height as i64);
            sm.set("ColorSpace", Object::Name(b"DeviceGray".to_vec()));
            sm.set("BitsPerComponent", 8i64);
            objects.push((smask_id, seal(smask_id, stream(sm, &alpha, true))?));

            let mut im = Dictionary::new();
            im.set("Type", Object::Name(b"XObject".to_vec()));
            im.set("Subtype", Object::Name(b"Image".to_vec()));
            im.set("Width", img.width as i64);
            im.set("Height", img.height as i64);
            im.set("ColorSpace", Object::Name(b"DeviceRGB".to_vec()));
            im.set("BitsPerComponent", 8i64);
            im.set("SMask", Object::Reference(smask_id));
            objects.push((image_id, seal(image_id, stream(im, &rgb, true))?));

            let content = format!("q {w_pt} 0 0 {h_pt} 0 0 cm /Im1 Do Q\n");
            let mut form = Dictionary::new();
            form.set("Type", Object::Name(b"XObject".to_vec()));
            form.set("Subtype", Object::Name(b"Form".to_vec()));
            form.set("BBox", Object::Array(vec![0.into(), 0.into(), Object::Real(w_pt), Object::Real(h_pt)]));
            form.set("Matrix", Object::Array(geom.appearance_matrix().iter().map(|&v| Object::Integer(v as i64)).collect()));
            let mut xobjs = Dictionary::new();
            xobjs.set("Im1", Object::Reference(image_id));
            let mut res = Dictionary::new();
            res.set("XObject", xobjs);
            form.set("Resources", res);
            objects.push((form_id, seal(form_id, stream(form, content.as_bytes(), false))?));

            let mut ap = Dictionary::new();
            ap.set("N", Object::Reference(form_id));
            widget.set("AP", ap);
        }
        None => widget.set("Rect", Object::Array(vec![0.into(), 0.into(), 0.into(), 0.into()])),
    }
    objects.push((widget_id, seal(widget_id, Object::Dictionary(widget))?));

    // Page: append the widget to /Annots.
    let mut page = doc.get_dictionary(page_id).map_err(|_| anyhow!("{}: /Page", t().err_pdf_structure))?.clone();
    let mut annots = resolve_array(&doc, page.get(b"Annots").ok());
    annots.push(Object::Reference(widget_id));
    page.set("Annots", annots);
    objects.push((page_id, seal(page_id, Object::Dictionary(page))?));

    // AcroForm: add the field and mark the document as signed.
    let update_form = |form: &mut Dictionary| {
        let mut fields = resolve_array(&doc, form.get(b"Fields").ok());
        fields.push(Object::Reference(widget_id));
        form.set("Fields", fields);
        form.set("SigFlags", 3i64);
    };
    match catalog.get(b"AcroForm") {
        Ok(Object::Reference(form_id)) => {
            let form_id = *form_id;
            let mut form = doc.get_dictionary(form_id).map_err(|_| anyhow!("{}: /AcroForm", t().err_pdf_structure))?.clone();
            update_form(&mut form);
            objects.push((form_id, seal(form_id, Object::Dictionary(form))?));
        }
        other => {
            let mut form = match other {
                Ok(Object::Dictionary(d)) => d.clone(),
                _ => Dictionary::new(),
            };
            update_form(&mut form);
            catalog.set("AcroForm", form);
            objects.push((root_id, seal(root_id, Object::Dictionary(catalog))?));
        }
    }

    // Signature dictionary with placeholders.
    let mut sig = Vec::new();
    let contents_len = match &kind {
        Kind::Signature { req, signer, timestamp, .. } => {
            sig.extend_from_slice(b"<</Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached");
            let m = req.time.format("D:%Y%m%d%H%M%S%:z").to_string();
            let m = format!("{}'{}'", &m[..m.len() - 3], &m[m.len() - 2..]);
            let strings = [
                ("Name", text(req.signer_name.trim())),
                ("Reason", text(req.reason.trim())),
                ("Location", text(req.location.trim())),
                ("ContactInfo", text(req.contact.trim())),
                ("M", Object::String(m.into_bytes(), lopdf::StringFormat::Literal)),
            ];
            for (key, val) in strings {
                if matches!(&val, Object::String(s, _) if s.len() <= 2 && key != "M") {
                    continue;
                }
                write!(sig, " /{key} ").unwrap();
                sig.extend(seal(sig_id, val)?);
            }
            // A time-stamp token carries the TSA's certificate chain.
            let ts_room = if timestamp.is_some() { 24_000 } else { 0 };
            (signer.chain.iter().map(|c| c.len()).sum::<usize>() + 6000 + ts_room) * 2
        }
        Kind::DocTimeStamp { .. } => {
            sig.extend_from_slice(b"<</Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161");
            24_000 * 2
        }
    };
    sig.extend_from_slice(b" /ByteRange ");
    let br_off = sig.len();
    sig.extend_from_slice(b"[0 0000000000 0000000000 0000000000]");
    let br_len = sig.len() - br_off;
    sig.extend_from_slice(b" /Contents ");
    let contents_off = sig.len();
    sig.push(b'<');
    sig.resize(sig.len() + contents_len, b'0');
    sig.push(b'>');
    sig.extend_from_slice(b">>");
    objects.push((sig_id, sig));

    let encrypt = encrypt_ref(crypt, &mut next_id, &mut objects)?;
    let (mut out, bodies) = write_update(input, &doc, &objects, &mut next_id, encrypt)?;
    let sig_body_off = bodies[&sig_id];

    // Fill ByteRange, hash, sign, embed CMS.
    let c_start = sig_body_off + contents_off;
    let c_end = c_start + contents_len + 2;
    let br = format!("[0 {} {} {}]", c_start, c_end, out.len() - c_end);
    if br.len() > br_len {
        bail!(t().err_too_large);
    }
    let br_pos = sig_body_off + br_off;
    out[br_pos..br_pos + br_len].copy_from_slice(format!("{br:<br_len$}").as_bytes());

    let mut h = Sha256::new();
    h.update(&out[..c_start]);
    h.update(&out[c_end..]);
    let doc_digest = h.finalize();

    let cms_der = match kind {
        Kind::Signature { signer, sign, timestamp, .. } => {
            let attrs = cms::signed_attributes(&doc_digest, &signer.der);
            let signature = sign(&attrs)?;
            let token = match timestamp {
                Some(ts) => Some(ts(&cms::signature_value(&signature, signer.alg))?),
                None => None,
            };
            cms::build_signed_data(&attrs, &signature, signer, token.as_deref())
        }
        Kind::DocTimeStamp { tsa } => tsa(&doc_digest)?,
    };
    let hex: String = cms_der.iter().map(|b| format!("{b:02X}")).collect();
    if hex.len() > contents_len {
        bail!(t().err_sig_too_big);
    }
    out[c_start + 1..c_start + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_standalone(a: &Appearance) {
        let doc = Document::load_mem(&a.pdf).expect("standalone PDF loads");
        let pages = doc.get_pages();
        assert_eq!(pages.len(), 1);
        let page = doc.get_dictionary(*pages.values().next().unwrap()).unwrap();
        let mb = rect_of(&doc, page.get(b"MediaBox").unwrap()).unwrap();
        assert!((mb[2] - a.size.0).abs() < 0.5 && (mb[3] - a.size.1).abs() < 0.5);
    }

    #[test]
    fn finds_the_appearance_of_a_third_party_signature() {
        let bytes = include_bytes!("../tests/fixtures/signed-by-pyhanko.pdf");
        let found = signature_appearances(bytes).unwrap();
        assert_eq!(found.len(), 1);
        let a = &found[0];
        assert_eq!(a.page, 0);
        assert!(a.signer.contains("Fixture Signer"), "{}", a.signer);
        assert!((a.size.0 - 220.0).abs() < 1.0 && (a.size.1 - 70.0).abs() < 1.0, "{:?}", a.size);
        check_standalone(a);
    }

    #[test]
    fn finds_the_appearance_written_by_this_app() {
        let bytes = include_bytes!("../tests/fixtures/minimal.pdf");
        let signer = SignerCert { der: vec![0x30, 0], issuer_der: vec![0x30, 0], serial_be: vec![1], chain: vec![vec![0x30, 0]], alg: cms::KeyAlg::Rsa };
        let data = crate::style::StampData {
            name: "Test Signer".into(),
            issuer: String::new(),
            reason: String::new(),
            location: String::new(),
            contact: String::new(),
            time: Local::now(),
        };
        let style = crate::style::builtins().remove(0);
        let image = stamp::render(&style, &data, 190.0, 62.0, 2.0);
        let req = SignRequest {
            signer_name: "Test Signer".into(),
            reason: String::new(),
            location: String::new(),
            contact: String::new(),
            time: Local::now(),
            visible: Some(Visible { page: 0, rect: [100.0, 100.0, 190.0, 62.0], image }),
            password: None,
        };
        // The CMS is not valid here, which does not matter for the appearance.
        let signed = sign_pdf(bytes, &req, &signer, &|_| Ok(vec![0u8; 256]), None).unwrap();
        let found = signature_appearances(&signed).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].signer, "Test Signer");
        assert!((found[0].size.0 - 190.0).abs() < 0.5);
        check_standalone(&found[0]);
        assert!(signature_appearances(bytes).unwrap().is_empty());
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/encrypted/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn locked(r: Result<PdfInfo>) -> Option<Locked> {
        r.err().and_then(|e| e.downcast_ref::<Locked>().copied())
    }

    #[test]
    fn encrypted_pdfs_open_with_the_right_password_only() {
        for name in ["rc4-40-owner.pdf", "aes-128-owner.pdf"] {
            assert!(inspect(&fixture(name), None).unwrap().encrypted, "{name}: owner password only, opens as is");
        }
        for name in ["rc4-128-user.pdf", "aes-256-user.pdf"] {
            let bytes = fixture(name);
            assert_eq!(locked(inspect(&bytes, None)), Some(Locked::NeedsPassword), "{name}");
            assert_eq!(locked(inspect(&bytes, Some("nope"))), Some(Locked::WrongPassword), "{name}");
            assert!(inspect(&bytes, Some("user")).unwrap().encrypted, "{name}");
            assert!(inspect(&bytes, Some("owner")).unwrap().encrypted, "{name}");
        }
        let restricted = fixture("aes-256-no-signing.pdf");
        assert_eq!(locked(inspect(&restricted, None)), Some(Locked::SigningNotAllowed));
        assert_eq!(locked(inspect(&restricted, Some("wrong"))), Some(Locked::WrongPassword));
        assert!(inspect(&restricted, Some("owner")).is_ok(), "the owner password lifts the restriction");
        assert!(!inspect(include_bytes!("../tests/fixtures/minimal.pdf"), None).unwrap().encrypted);
    }

    #[test]
    fn signs_encrypted_pdfs_with_encrypted_new_objects() {
        let signer = SignerCert { der: vec![0x30, 0], issuer_der: vec![0x30, 0], serial_be: vec![1], chain: vec![vec![0x30, 0]], alg: cms::KeyAlg::Rsa };
        let data = crate::style::StampData { name: "Тест Signer".into(), issuer: String::new(), reason: "Одобрено".into(), location: String::new(), contact: String::new(), time: Local::now() };
        let cases = [("rc4-40-owner.pdf", None), ("rc4-128-user.pdf", Some("user")), ("aes-128-owner.pdf", None), ("aes-256-user.pdf", Some("user")), ("aes-256-no-signing.pdf", Some("owner"))];
        for (name, password) in cases {
            let input = fixture(name);
            let req = SignRequest {
                signer_name: "Тест Signer".into(),
                reason: "Одобрено".into(),
                location: String::new(),
                contact: String::new(),
                time: Local::now(),
                visible: Some(Visible { page: 0, rect: [100.0, 100.0, 190.0, 62.0], image: stamp::render(&crate::style::builtins().remove(0), &data, 190.0, 62.0, 2.0) }),
                password: password.map(str::to_string),
            };
            let signed = sign_pdf(&input, &req, &signer, &|_| Ok(vec![0u8; 256]), None).unwrap();
            let tail = &signed[input.len()..];
            assert!(!tail.windows(9).any(|w| w == b"Signature"), "{name}: field name is encrypted");
            assert!(tail.windows(14).any(|w| w == b"/Contents <308"), "{name}: /Contents stays plain");
            assert!(tail.windows(9).any(|w| w == b"/Encrypt "), "{name}: trailer keeps /Encrypt");

            let doc = load(&signed, password).unwrap();
            let sig = doc.objects.values().filter_map(|o| o.as_dict().ok()).find(|d| d.get(b"ByteRange").is_ok()).expect("signature dictionary");
            assert_eq!(pdf_text(sig.get(b"Name").unwrap().as_str().unwrap()), "Тест Signer", "{name}");
            assert_eq!(pdf_text(sig.get(b"Reason").unwrap().as_str().unwrap()), "Одобрено", "{name}");
            assert!(sig.get(b"M").unwrap().as_str().unwrap().starts_with(b"D:20"), "{name}");
            let field = sig_fields(&doc).find(|d| d.get(b"V").is_ok()).unwrap();
            assert_eq!(pdf_text(field.get(b"T").unwrap().as_str().unwrap()), "Signature1", "{name}");
            let rgb = doc.objects.values().filter_map(|o| o.as_stream().ok()).find(|s| s.dict.get(b"SMask").is_ok()).expect("stamp image");
            let (w, h) = (rgb.dict.get(b"Width").unwrap().as_i64().unwrap(), rgb.dict.get(b"Height").unwrap().as_i64().unwrap());
            assert_eq!(rgb.decompressed_content().unwrap().len() as i64, w * h * 3, "{name}: stamp image decrypts and inflates");
            assert_eq!(inspect(&signed, password).unwrap().signatures, 1, "{name}");
        }
        let err = sign_pdf(&fixture("aes-256-no-signing.pdf"), &SignRequest { signer_name: "x".into(), reason: String::new(), location: String::new(), contact: String::new(), time: Local::now(), visible: None, password: None }, &signer, &|_| Ok(vec![0u8; 256]), None);
        assert_eq!(locked(err.map(|_| PdfInfo { pages: vec![], signatures: 0, encrypted: true })), Some(Locked::SigningNotAllowed));
    }

    #[test]
    fn signing_twice_gives_unique_field_names() {
        let signer = SignerCert { der: vec![0x30, 0], issuer_der: vec![0x30, 0], serial_be: vec![1], chain: vec![vec![0x30, 0]], alg: cms::KeyAlg::Rsa };
        let req = SignRequest { signer_name: "x".into(), reason: String::new(), location: String::new(), contact: String::new(), time: Local::now(), visible: None, password: None };
        let once = sign_pdf(include_bytes!("../tests/fixtures/minimal.pdf"), &req, &signer, &|_| Ok(vec![0u8; 256]), None).unwrap();
        let twice = sign_pdf(&once, &req, &signer, &|_| Ok(vec![0u8; 256]), None).unwrap();
        let doc = load(&twice, None).unwrap();
        let mut names: Vec<String> = sig_fields(&doc).filter_map(|d| d.get(b"T").ok()?.as_str().ok().map(pdf_text)).collect();
        names.sort();
        assert_eq!(names, ["Signature1", "Signature2"]);
    }

    #[test]
    fn rotation_maps_display_rect_to_user_space() {
        let g = PageGeom { crop: [0.0, 0.0, 600.0, 800.0], rotate: 0 };
        assert_eq!(g.display_rect_to_user([10.0, 20.0, 100.0, 50.0]), [10.0, 730.0, 110.0, 780.0]);
        let g = PageGeom { crop: [0.0, 0.0, 600.0, 800.0], rotate: 90 };
        assert_eq!(g.display_size(), (800.0, 600.0));
        // Top-left of the displayed page is the user-space origin for a 90° page.
        assert_eq!(g.display_rect_to_user([0.0, 0.0, 100.0, 50.0]), [0.0, 0.0, 50.0, 100.0]);
    }

    /// End-to-end with a real certificate from the user's store (Windows) or
    /// certificate folder (Linux):
    /// `DOC_SIGNER_TEST_PDF=in.pdf DOC_SIGNER_THUMB=<sha1> cargo test -- --include-ignored`
    ///
    /// Optional overrides: `DOC_SIGNER_NAME`, `DOC_SIGNER_REASON`, `DOC_SIGNER_LOCATION`,
    /// `DOC_SIGNER_CONTACT`, `DOC_SIGNER_RECT="x y w h"` (points), `DOC_SIGNER_PAGE` (0-based).
    #[test]
    #[ignore]
    fn signs_with_real_certificate() {
        let (Ok(input), Ok(thumb_hex)) = (std::env::var("DOC_SIGNER_TEST_PDF"), std::env::var("DOC_SIGNER_THUMB")) else {
            eprintln!("SKIPPED signs_with_real_certificate: set DOC_SIGNER_TEST_PDF and DOC_SIGNER_THUMB to run it");
            return;
        };
        let thumb: Vec<u8> = (0..thumb_hex.len()).step_by(2).map(|i| u8::from_str_radix(&thumb_hex[i..i + 2], 16).unwrap()).collect();
        let signer = crate::certs::load_signer(&thumb).unwrap();
        let bytes = std::fs::read(&input).unwrap();
        // Optional DOC_SIGNER_PDF_PASSWORD for encrypted input.
        let password = std::env::var("DOC_SIGNER_PDF_PASSWORD").ok();
        let info = inspect(&bytes, password.as_deref()).unwrap();
        let env_or = |k: &str, d: String| std::env::var(k).unwrap_or(d);
        let (page, rect) = match std::env::var("DOC_SIGNER_RECT").ok() {
            Some(s) => {
                let r: Vec<f32> = s.split_whitespace().map(|p| p.parse().unwrap()).collect();
                let page = std::env::var("DOC_SIGNER_PAGE").ok().and_then(|p| p.parse().ok()).unwrap_or(info.pages.len() - 1);
                (page, [r[0], r[1], r[2], r[3]])
            }
            None => (info.pages.len() - 1, [300.0, 600.0, 190.0, 62.0]),
        };
        let (signer_name, reason, location, contact) = (
            env_or("DOC_SIGNER_NAME", "Test Signer".into()),
            env_or("DOC_SIGNER_REASON", "Approved".into()),
            env_or("DOC_SIGNER_LOCATION", "Testville".into()),
            env_or("DOC_SIGNER_CONTACT", String::new()),
        );
        let time = chrono::Local::now();
        // Optional DOC_SIGNER_STYLE=<style.json>; default is the built-in "Classic" style.
        let style = match std::env::var("DOC_SIGNER_STYLE") {
            Ok(p) => crate::style::parse(&std::fs::read_to_string(p).unwrap()).unwrap(),
            Err(_) => crate::style::builtins().remove(0),
        };
        let data = crate::style::StampData {
            name: signer_name.clone(),
            issuer: String::new(),
            reason: reason.clone(),
            location: location.clone(),
            contact: contact.clone(),
            time,
        };
        let image = stamp::render(&style, &data, rect[2], rect[3], 4.0);
        let req = SignRequest { signer_name, reason, location, contact, time, visible: Some(Visible { page, rect, image }), password: password.clone() };
        // Optional DOC_SIGNER_TSA=<url>: add an RFC 3161 time-stamp (PAdES B-T).
        let tsa = std::env::var("DOC_SIGNER_TSA").ok();
        let ts = |v: &[u8]| crate::tsa::timestamp(tsa.as_deref().unwrap(), v).map(|t| t.token);
        let ts_ref: Option<Timestamper> = if tsa.is_some() { Some(&ts) } else { None };
        let mut out = sign_pdf(&bytes, &req, &signer, &|d| crate::certs::sign_data(&thumb, d, signer.alg), ts_ref).unwrap();
        // Optional DOC_SIGNER_LTV=1 (B-LT) / DOC_SIGNER_LTA=1 (B-LTA, with DOC_SIGNER_TSA).
        if std::env::var("DOC_SIGNER_LTV").is_ok() || std::env::var("DOC_SIGNER_LTA").is_ok() {
            let archive = std::env::var("DOC_SIGNER_LTA").is_ok().then(|| tsa.clone().expect("DOC_SIGNER_LTA needs DOC_SIGNER_TSA"));
            let (extended, warnings) = crate::ltv::extend(&out, password.as_deref(), archive.as_deref(), &crate::ltv::Http).unwrap();
            for w in &warnings {
                eprintln!("LTV warning: {w}");
            }
            assert!(warnings.is_empty(), "complete validation data expected");
            out = extended;
        }
        std::fs::write(format!("{input}.signed.pdf"), &out).unwrap();
        let doc_timestamps = usize::from(std::env::var("DOC_SIGNER_LTA").is_ok());
        assert_eq!(inspect(&out, password.as_deref()).unwrap().signatures, info.signatures + 1 + doc_timestamps);
    }
}
