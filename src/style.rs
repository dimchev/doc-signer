//! Named stamp styles: model (JSON, `version` 1), built-in styles, storage and import/export.
//!
//! The "Digitally signed by" label and the signer's name are mandatory in every style, so a
//! visible stamp always names the real signer (see `normalize`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::i18n::t;

pub const VERSION: u32 = 1;
pub const DEFAULT_DATE_FORMAT: &str = "%d.%m.%Y %H:%M:%S %:z";
pub const CLASSIC_ID: &str = "builtin:classic";

/// sRGB colour, stored as `#RRGGBB`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rgb(pub [u8; 3]);

impl Rgb {
    pub const INK: Rgb = Rgb([0x1a, 0x3e, 0x8c]);
    pub const TEAL: Rgb = Rgb([0x00, 0xa1, 0x9a]);
    pub const WHITE: Rgb = Rgb([0xff, 0xff, 0xff]);

    pub fn hex(self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.0[0], self.0[1], self.0[2])
    }

    pub fn parse(s: &str) -> Option<Rgb> {
        let h = s.trim().strip_prefix('#')?;
        if h.len() != 6 {
            return None;
        }
        let v = u32::from_str_radix(h, 16).ok()?;
        Some(Rgb([(v >> 16) as u8, (v >> 8) as u8, v as u8]))
    }
}

impl Serialize for Rgb {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for Rgb {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Rgb::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("invalid colour '{s}', expected #RRGGBB")))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Shape {
    Rect,
    Rounded { radius: f32 },
    Ellipse,
    /// Round seal: text along the top and bottom arcs (see [`SealSpec`]).
    Seal,
    None,
}

/// Texts of a round seal. Placeholders: `{label}`, `{name}`, `{date}`, `{reason}`, `{location}`,
/// `{issuer}`, `{contact}`. `{label}` and `{name}` are always present (see `Style::normalize`).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SealSpec {
    pub top: String,
    pub bottom: String,
    #[serde(default = "seal_date_format")]
    pub date_format: String,
    #[serde(default = "yes")]
    pub uppercase: bool,
    /// ✓ in the centre when the style has no picture.
    #[serde(default = "yes")]
    pub check: bool,
}

fn seal_date_format() -> String {
    "%d.%m.%Y".into()
}

impl Default for SealSpec {
    fn default() -> Self {
        SealSpec { top: "{label} • {name}".into(), bottom: "{date}".into(), date_format: seal_date_format(), uppercase: true, check: true }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub struct Size {
    pub w: f32,
    pub h: f32,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub struct Palette {
    pub text: Rgb,
    pub border: Rgb,
    pub background: Rgb,
    #[serde(default)]
    pub background_opacity: f32,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum BorderStyle {
    Single,
    Double,
    Dashed,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub struct Border {
    pub width: f32,
    pub style: BorderStyle,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FontFamily {
    Sans,
    Serif,
    Mono,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Align {
    Left,
    Center,
    Right,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub struct FontSpec {
    pub family: FontFamily,
    /// Fixed size in points; `None` = fit automatically.
    #[serde(default)]
    pub size: Option<f32>,
    pub align: Align,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Label,
    Name,
    Date,
    Reason,
    Location,
    Issuer,
    Contact,
    Custom,
}

impl FieldKind {
    pub fn mandatory(self) -> bool {
        matches!(self, FieldKind::Label | FieldKind::Name)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ImagePosition {
    Left,
    Right,
    Top,
    /// Behind the text (watermark).
    Background,
}

/// A picture in the stamp: handwritten signature, logo or company seal.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StyleImage {
    /// PNG, base64 (so exported styles are self-contained). Empty = no picture yet.
    #[serde(default)]
    pub png_base64: String,
    pub position: ImagePosition,
    #[serde(default = "one")]
    pub opacity: f32,
    /// Luminance threshold (0.5-0.99) above which pixels become transparent; `None` = keep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_background: Option<f32>,
}

impl StyleImage {
    pub fn is_empty(&self) -> bool {
        self.png_base64.is_empty()
    }
}

fn yes() -> bool {
    true
}
fn one() -> f32 {
    1.0
}
fn version() -> u32 {
    VERSION
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Field {
    pub kind: FieldKind,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub bold: bool,
    /// Relative size (1.0 = base line size).
    #[serde(default = "one")]
    pub scale: f32,
    /// Show the translated caption ("Date: …", "Reason: …").
    #[serde(default = "yes")]
    pub prefix: bool,
    /// Text of a `custom` field; may contain `{name}`, `{date}`, `{reason}`, `{location}`, `{issuer}`, `{contact}`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// chrono format of a `date` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

impl Field {
    pub fn new(kind: FieldKind) -> Field {
        Field { kind, enabled: true, bold: false, scale: 1.0, prefix: true, text: String::new(), format: None }
    }

    fn bold(mut self, scale: f32) -> Field {
        self.bold = true;
        self.scale = scale;
        self
    }

    fn off(mut self) -> Field {
        self.enabled = false;
        self
    }

    fn no_prefix(mut self) -> Field {
        self.prefix = false;
        self
    }

    fn format(mut self, f: &str) -> Field {
        self.format = Some(f.into());
        self
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Style {
    #[serde(default = "version")]
    pub version: u32,
    #[serde(default)]
    pub id: String,
    pub name: String,
    /// Read-only (e.g. a distributed corporate style); can only be duplicated.
    #[serde(default)]
    pub locked: bool,
    #[serde(skip)]
    pub builtin: bool,
    pub shape: Shape,
    pub size: Size,
    pub palette: Palette,
    pub border: Border,
    pub font: FontSpec,
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<StyleImage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealSpec>,
}

/// Values shown in a stamp.
#[derive(Clone, Debug)]
pub struct StampData {
    pub name: String,
    pub issuer: String,
    pub reason: String,
    pub location: String,
    pub contact: String,
    pub time: DateTime<Local>,
}

/// One rendered text line.
#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    pub text: String,
    pub bold: bool,
    pub scale: f32,
}

fn format_date(time: &DateTime<Local>, format: &str) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    // An invalid user format makes chrono's Display fail; fall back to the default.
    if write!(s, "{}", time.format(format)).is_err() {
        s.clear();
        let _ = write!(s, "{}", time.format(DEFAULT_DATE_FORMAT));
    }
    s
}

impl StampData {
    fn expand(&self, template: &str, date: &str) -> String {
        template
            .replace("{label}", t().stamp_signed_by)
            .replace("{name}", &self.name)
            .replace("{date}", date)
            .replace("{reason}", self.reason.trim())
            .replace("{location}", self.location.trim())
            .replace("{issuer}", &self.issuer)
            .replace("{contact}", self.contact.trim())
    }
}

impl Style {
    pub fn read_only(&self) -> bool {
        self.builtin || self.locked
    }

    /// Enforces the invariants: label + name present and enabled, sane sizes.
    pub fn normalize(&mut self) {
        if !self.fields.iter().any(|f| f.kind == FieldKind::Label) {
            self.fields.insert(0, Field::new(FieldKind::Label));
        }
        if !self.fields.iter().any(|f| f.kind == FieldKind::Name) {
            let at = self.fields.iter().position(|f| f.kind == FieldKind::Label).map_or(0, |i| i + 1);
            self.fields.insert(at, Field::new(FieldKind::Name).bold(1.45));
        }
        for f in &mut self.fields {
            if f.kind.mandatory() {
                f.enabled = true;
            }
            f.scale = f.scale.clamp(0.5, 3.0);
        }
        self.size.w = self.size.w.clamp(40.0, 600.0);
        self.size.h = self.size.h.clamp(20.0, 400.0);
        self.border.width = self.border.width.clamp(0.0, 10.0);
        self.palette.background_opacity = self.palette.background_opacity.clamp(0.0, 1.0);
        if let Shape::Rounded { radius } = &mut self.shape {
            *radius = radius.clamp(0.0, 100.0);
        }
        if let Some(s) = &mut self.font.size {
            *s = s.clamp(3.0, 72.0);
        }
        if self.shape == Shape::Seal {
            // A seal is round; its arcs must name the real signer.
            self.size.h = self.size.w;
            let seal = self.seal.get_or_insert_with(SealSpec::default);
            let all = format!("{} {}", seal.top, seal.bottom);
            if !all.contains("{name}") {
                seal.top = format!("{} • {{name}}", seal.top.trim()).trim_start_matches(" • ").to_string();
            }
            if !all.contains("{label}") {
                seal.top = format!("{{label}} • {}", seal.top.trim()).trim_end_matches(" • ").to_string();
            }
        }
        if let Some(img) = &mut self.image {
            img.opacity = img.opacity.clamp(0.05, 1.0);
            if let Some(t) = &mut img.remove_background {
                *t = t.clamp(0.5, 0.99);
            }
        }
    }

    /// Identity of everything that affects rendering, with the image data replaced by its hash
    /// (cheap to compare every frame).
    pub fn fingerprint(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut c = self.clone();
        if let Some(img) = &mut c.image {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            img.png_base64.hash(&mut h);
            img.png_base64 = format!("{}:{:x}", img.png_base64.len(), h.finish());
        }
        to_json(&c)
    }

    /// Expanded (top, bottom) arc texts of a seal.
    pub fn seal_texts(&self, d: &StampData) -> Option<(String, String)> {
        let seal = self.seal.as_ref()?;
        let date = format_date(&d.time, &seal.date_format);
        let fix = |s: String| {
            let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
            if seal.uppercase { s.to_uppercase() } else { s }
        };
        Some((fix(d.expand(&seal.top, &date)), fix(d.expand(&seal.bottom, &date))))
    }

    /// The text lines of this style for the given values; empty optional fields are skipped.
    pub fn lines(&self, d: &StampData) -> Vec<Line> {
        let default_date = format_date(&d.time, DEFAULT_DATE_FORMAT);
        let tr = t();
        let mut out = Vec::new();
        for f in self.fields.iter().filter(|f| f.enabled) {
            let date = format_date(&d.time, f.format.as_deref().unwrap_or(DEFAULT_DATE_FORMAT));
            let (caption, value) = match f.kind {
                FieldKind::Label => ("", tr.stamp_signed_by.to_string()),
                FieldKind::Name => ("", d.name.clone()),
                FieldKind::Date => (tr.stamp_date, date),
                FieldKind::Reason => (tr.reason, d.reason.trim().to_string()),
                FieldKind::Location => (tr.location, d.location.trim().to_string()),
                FieldKind::Issuer => (tr.issuer, d.issuer.clone()),
                FieldKind::Contact => (tr.contact, d.contact.trim().to_string()),
                FieldKind::Custom => ("", d.expand(&f.text, &default_date).trim().to_string()),
            };
            if value.is_empty() && !f.kind.mandatory() {
                continue;
            }
            let text = if f.prefix && !caption.is_empty() { format!("{caption}: {value}") } else { value };
            out.push(Line { text, bold: f.bold, scale: f.scale });
        }
        out
    }
}

// ---------- built-in styles ----------

fn base(id: &str, name: &str) -> Style {
    Style {
        version: VERSION,
        id: id.into(),
        name: name.into(),
        locked: false,
        builtin: true,
        shape: Shape::Rect,
        size: Size { w: 190.0, h: 62.0 },
        palette: Palette { text: Rgb::INK, border: Rgb::INK, background: Rgb::WHITE, background_opacity: 0.0 },
        border: Border { width: 0.8, style: BorderStyle::Single },
        font: FontSpec { family: FontFamily::Sans, size: None, align: Align::Left },
        fields: vec![
            Field::new(FieldKind::Label),
            Field::new(FieldKind::Name).bold(1.45),
            Field::new(FieldKind::Date),
            Field::new(FieldKind::Reason),
            Field::new(FieldKind::Location),
            Field::new(FieldKind::Issuer).off(),
            Field::new(FieldKind::Contact).off(),
        ],
        image: None,
        seal: None,
    }
}

/// Built-in, read-only styles (names in the current language).
pub fn builtins() -> Vec<Style> {
    let tr = &t().style;
    let classic = base(CLASSIC_ID, tr.classic);

    let mut minimal = base("builtin:minimal", tr.minimal);
    minimal.shape = Shape::None;
    minimal.size = Size { w: 170.0, h: 44.0 };
    minimal.fields = vec![
        Field::new(FieldKind::Label).bold(0.85),
        Field::new(FieldKind::Name).bold(1.35),
        Field::new(FieldKind::Date).no_prefix().format("%d.%m.%Y %H:%M"),
    ];

    let mut badge = base("builtin:badge", tr.badge);
    badge.shape = Shape::Rounded { radius: 8.0 };
    badge.palette = Palette { text: Rgb::WHITE, border: Rgb::INK, background: Rgb::INK, background_opacity: 1.0 };
    badge.border.width = 0.0;
    badge.font.align = Align::Center;

    let mut corporate = base("builtin:corporate", tr.corporate);
    corporate.shape = Shape::Rounded { radius: 4.0 };
    corporate.palette = Palette { text: Rgb::INK, border: Rgb::TEAL, background: Rgb::TEAL, background_opacity: 0.08 };
    corporate.border = Border { width: 1.0, style: BorderStyle::Double };
    corporate.size = Size { w: 200.0, h: 66.0 };

    let mut handwritten = base("builtin:handwritten", tr.handwritten);
    handwritten.shape = Shape::None;
    handwritten.size = Size { w: 210.0, h: 60.0 };
    handwritten.fields = vec![
        Field::new(FieldKind::Label),
        Field::new(FieldKind::Name).bold(1.3),
        Field::new(FieldKind::Date).no_prefix().format("%d.%m.%Y %H:%M"),
    ];
    handwritten.image = Some(StyleImage { png_base64: String::new(), position: ImagePosition::Left, opacity: 1.0, remove_background: Some(0.9) });

    let mut seal = base("builtin:seal", tr.seal_style);
    seal.shape = Shape::Seal;
    seal.size = Size { w: 110.0, h: 110.0 };
    seal.border = Border { width: 1.4, style: BorderStyle::Double };
    seal.seal = Some(SealSpec::default());

    let mut v = vec![classic, minimal, badge, corporate, handwritten, seal];
    for s in &mut v {
        s.normalize();
    }
    v
}

// ---------- storage ----------

pub fn dir() -> Option<PathBuf> {
    crate::settings::app_dir().map(|d| d.join("styles"))
}

pub fn new_id() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = Local::now().timestamp_nanos_opt().unwrap_or_default();
    format!("{nanos:x}{:x}", N.fetch_add(1, Ordering::Relaxed))
}

fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Parses and validates a style file (used for stored and imported styles).
pub fn parse(json: &str) -> Result<Style> {
    let mut s: Style = serde_json::from_str(json)?;
    if s.version > VERSION {
        bail!("{} (version {})", t().style.err_newer, s.version);
    }
    s.version = VERSION;
    s.builtin = false;
    s.normalize();
    Ok(s)
}

pub fn to_json(s: &Style) -> String {
    serde_json::to_string_pretty(s).expect("style serializes")
}

/// User styles from the styles folder; unreadable files are reported, not fatal.
pub fn load_user() -> (Vec<Style>, Vec<String>) {
    let mut styles = Vec::new();
    let mut errors = Vec::new();
    let Some(dir) = dir() else { return (styles, errors) };
    let Ok(rd) = std::fs::read_dir(&dir) else { return (styles, errors) };
    for e in rd.flatten() {
        let p = e.path();
        if !p.extension().is_some_and(|x| x.eq_ignore_ascii_case("json")) {
            continue;
        }
        match std::fs::read_to_string(&p).map_err(anyhow::Error::from).and_then(|j| parse(&j)) {
            Ok(mut s) => {
                s.id = p.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                styles.push(s);
            }
            Err(err) => errors.push(format!("{}: {err:#}", p.display())),
        }
    }
    styles.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    (styles, errors)
}

pub fn save(s: &Style) -> Result<()> {
    if s.builtin || !safe_id(&s.id) {
        bail!("{}", t().style.err_save);
    }
    let dir = dir().context(t().style.err_save)?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(format!("{}.json", s.id)), to_json(s))?;
    Ok(())
}

pub fn delete(id: &str) -> Result<()> {
    if !safe_id(id) {
        bail!("{}", t().style.err_save);
    }
    let dir = dir().context(t().style.err_save)?;
    std::fs::remove_file(dir.join(format!("{id}.json")))?;
    Ok(())
}

pub fn export(s: &Style, path: &Path) -> Result<()> {
    let mut copy = s.clone();
    copy.builtin = false;
    std::fs::write(path, to_json(&copy))?;
    Ok(())
}

pub fn import(path: &Path) -> Result<Style> {
    let json = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let mut s = parse(&json).with_context(|| path.display().to_string())?;
    s.id = new_id();
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> StampData {
        StampData {
            name: "Ivan Petrov".into(),
            issuer: "Test CA".into(),
            reason: " Approved ".into(),
            location: String::new(),
            contact: String::new(),
            time: chrono::TimeZone::with_ymd_and_hms(&Local, 2026, 11, 26, 9, 5, 0).unwrap(),
        }
    }

    #[test]
    fn json_round_trip_keeps_every_setting() {
        for mut s in builtins() {
            s.builtin = false;
            let back = parse(&to_json(&s)).unwrap();
            assert_eq!(back, s, "{}", s.name);
        }
    }

    #[test]
    fn label_and_name_are_mandatory() {
        let json = r##"{"name":"x","shape":{"kind":"rect"},"size":{"w":100,"h":40},
            "palette":{"text":"#000000","border":"#000000","background":"#FFFFFF"},
            "border":{"width":1,"style":"single"},"font":{"family":"sans","align":"left"},
            "fields":[{"kind":"date"},{"kind":"label","enabled":false}]}"##;
        let s = parse(json).unwrap();
        let kinds: Vec<_> = s.fields.iter().filter(|f| f.enabled).map(|f| f.kind).collect();
        assert_eq!(kinds, [FieldKind::Date, FieldKind::Label, FieldKind::Name]);
        let lines = s.lines(&data());
        assert!(lines.iter().any(|l| l.text == "Ivan Petrov"));
    }

    #[test]
    fn lines_skip_empty_fields_and_expand_placeholders() {
        let mut s = builtins().remove(0);
        let mut custom = Field::new(FieldKind::Custom);
        custom.text = "{name} / {reason}".into();
        s.fields.push(custom);
        let texts: Vec<String> = s.lines(&data()).into_iter().map(|l| l.text).collect();
        assert!(!texts.iter().any(|t| t.contains("Location") || t.ends_with(": ")));
        assert!(texts.contains(&"Ivan Petrov / Approved".to_string()));
    }

    #[test]
    fn seal_always_names_the_signer() {
        let mut s = builtins().into_iter().find(|s| s.shape == Shape::Seal).unwrap();
        assert_eq!(s.size.w, s.size.h);
        s.seal = Some(SealSpec { top: "ACME".into(), bottom: "{date}".into(), ..SealSpec::default() });
        s.size.h = 50.0;
        s.normalize();
        assert_eq!(s.size.h, s.size.w, "seal stays round");
        let (top, bottom) = s.seal_texts(&data()).unwrap();
        assert!(top.contains("IVAN PETROV") && top.contains("ACME"), "{top}");
        assert!(top.contains(&t().stamp_signed_by.to_uppercase()), "{top}");
        assert_eq!(bottom, "26.11.2026");
    }

    #[test]
    fn invalid_date_format_falls_back() {
        let d = data();
        assert_eq!(format_date(&d.time, "%Q-invalid"), format_date(&d.time, DEFAULT_DATE_FORMAT));
    }

    #[test]
    fn rejects_bad_colour_and_newer_version() {
        assert!(Rgb::parse("#12345").is_none());
        assert_eq!(Rgb::parse("#1a3e8c"), Some(Rgb::INK));
        let mut s = builtins().remove(0);
        s.version = VERSION + 1;
        assert!(parse(&to_json(&s)).is_err());
    }
}
