//! Rasterizes the visible signature stamp from a [`Style`] into an RGBA image.
//!
//! Shapes, borders and backgrounds are drawn with `tiny-skia`; text is converted from glyph
//! outlines (`ab_glyph`) into paths, so any Unicode (incl. Cyrillic) works without embedding
//! fonts into the PDF, and glyphs can be transformed freely.

use std::sync::OnceLock;

use ab_glyph::{Font, FontVec, GlyphId, OutlineCurve, PxScale, ScaleFont};
use tiny_skia::{FillRule, Paint, Path, PathBuilder, Pixmap, Rect, Stroke, StrokeDash, Transform};

use crate::fonts;
use crate::style::{Align, BorderStyle, FontFamily, Line, Rgb, Shape, StampData, Style};

/// Padding between the shape and the text, in points.
const PAD_PT: f32 = 4.0;
/// Largest automatic base line size, in points.
const MAX_AUTO_PT: f32 = 9.0;
const LEADING: f32 = 1.18;

struct Fonts {
    regular: FontVec,
    bold: FontVec,
    builtin: bool,
}

fn parse(bytes: Option<Vec<u8>>) -> Option<FontVec> {
    bytes.and_then(|b| FontVec::try_from_vec(b).ok())
}

/// System fonts of the family when available, otherwise the font bundled with egui,
/// so the stamp always has text.
fn fonts_for(family: FontFamily) -> &'static Fonts {
    static CACHE: [OnceLock<Fonts>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    let slot = match family {
        FontFamily::Sans => 0,
        FontFamily::Serif => 1,
        FontFamily::Mono => 2,
    };
    CACHE[slot].get_or_init(|| {
        let (regular_names, bold_names) = fonts::stamp_files(family);
        let regular_bytes = fonts::find(regular_names);
        match parse(regular_bytes.clone()) {
            Some(regular) => {
                let bold = parse(fonts::find(bold_names)).or_else(|| parse(regular_bytes)).expect("parsed above");
                Fonts { regular, bold, builtin: false }
            }
            None => {
                let font = || parse(Some(fonts::builtin())).expect("bundled font parses");
                Fonts { regular: font(), bold: font(), builtin: true }
            }
        }
    })
}

/// True when no suitable system sans font was found and the bundled fallback is used.
pub fn uses_builtin_font() -> bool {
    fonts_for(FontFamily::Sans).builtin
}

/// Unpremultiplied RGBA image of the stamp.
pub struct Rendered {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
    /// The text did not fit (only possible with a fixed font size).
    pub clipped: bool,
}

impl Rendered {
    pub fn rgb_and_alpha(&self) -> (Vec<u8>, Vec<u8>) {
        let n = (self.width * self.height) as usize;
        let mut rgb = Vec::with_capacity(n * 3);
        let mut alpha = Vec::with_capacity(n);
        for px in self.rgba.chunks_exact(4) {
            rgb.extend_from_slice(&px[..3]);
            alpha.push(px[3]);
        }
        (rgb, alpha)
    }
}

fn paint(c: Rgb, opacity: f32) -> Paint<'static> {
    let mut p = Paint::default();
    p.set_color_rgba8(c.0[0], c.0[1], c.0[2], (opacity.clamp(0.0, 1.0) * 255.0).round() as u8);
    p.anti_alias = true;
    p
}

fn rounded_rect(x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> Option<Path> {
    let r = r.min((x1 - x0) / 2.0).min((y1 - y0) / 2.0).max(0.0);
    if r <= 0.0 {
        return Some(PathBuilder::from_rect(Rect::from_ltrb(x0, y0, x1, y1)?));
    }
    // Cubic approximation of a quarter circle.
    let k = 0.552_284_8 * r;
    let mut pb = PathBuilder::new();
    pb.move_to(x0 + r, y0);
    pb.line_to(x1 - r, y0);
    pb.cubic_to(x1 - r + k, y0, x1, y0 + r - k, x1, y0 + r);
    pb.line_to(x1, y1 - r);
    pb.cubic_to(x1, y1 - r + k, x1 - r + k, y1, x1 - r, y1);
    pb.line_to(x0 + r, y1);
    pb.cubic_to(x0 + r - k, y1, x0, y1 - r + k, x0, y1 - r);
    pb.line_to(x0, y0 + r);
    pb.cubic_to(x0, y0 + r - k, x0 + r - k, y0, x0 + r, y0);
    pb.close();
    pb.finish()
}

/// Outline of the shape inset by `inset` pixels from the image edge.
fn shape_path(shape: Shape, w: f32, h: f32, inset: f32, scale: f32) -> Option<Path> {
    let (x0, y0, x1, y1) = (inset, inset, w - inset, h - inset);
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    match shape {
        Shape::Rect => Some(PathBuilder::from_rect(Rect::from_ltrb(x0, y0, x1, y1)?)),
        Shape::Rounded { radius } => rounded_rect(x0, y0, x1, y1, (radius * scale - inset).max(0.0)),
        Shape::Ellipse => PathBuilder::from_oval(Rect::from_ltrb(x0, y0, x1, y1)?),
        Shape::None => None,
    }
}

/// Appends the outline of one glyph at (`x`, `baseline`) to `pb` (pixel space, y down).
fn push_glyph(pb: &mut PathBuilder, font: &FontVec, id: GlyphId, px: f32, x: f32, baseline: f32) {
    let Some(outline) = font.outline(id) else { return };
    let sf = font.as_scaled(PxScale::from(px));
    let (sx, sy) = (sf.h_scale_factor(), sf.v_scale_factor());
    let map = |p: ab_glyph::Point| (x + p.x * sx, baseline - p.y * sy);
    let mut last: Option<ab_glyph::Point> = None;
    for curve in &outline.curves {
        let (start, end) = match *curve {
            OutlineCurve::Line(a, b) => (a, b),
            OutlineCurve::Quad(a, _, c) => (a, c),
            OutlineCurve::Cubic(a, _, _, d) => (a, d),
        };
        if last != Some(start) {
            if last.is_some() {
                pb.close();
            }
            let (mx, my) = map(start);
            pb.move_to(mx, my);
        }
        match *curve {
            OutlineCurve::Line(_, b) => {
                let (bx, by) = map(b);
                pb.line_to(bx, by);
            }
            OutlineCurve::Quad(_, b, c) => {
                let ((bx, by), (cx, cy)) = (map(b), map(c));
                pb.quad_to(bx, by, cx, cy);
            }
            OutlineCurve::Cubic(_, b, c, d) => {
                let ((bx, by), (cx, cy), (dx, dy)) = (map(b), map(c), map(d));
                pb.cubic_to(bx, by, cx, cy, dx, dy);
            }
        }
        last = Some(end);
    }
    if last.is_some() {
        pb.close();
    }
}

fn text_width(font: &FontVec, px: f32, text: &str) -> f32 {
    let sf = font.as_scaled(PxScale::from(px));
    let mut w = 0.0;
    let mut prev = None;
    for c in text.chars() {
        let g = sf.glyph_id(c);
        if let Some(p) = prev {
            w += sf.kern(p, g);
        }
        w += sf.h_advance(g);
        prev = Some(g);
    }
    w
}

/// Content area (x0, y0, x1, y1) inside the shape, in pixels.
fn content_box(style: &Style, w: f32, h: f32, scale: f32) -> (f32, f32, f32, f32) {
    let border = if style.shape == Shape::None { 0.0 } else { style.border.width * scale };
    let extra = if style.border.style == BorderStyle::Double { border * 2.5 } else { border };
    let pad = PAD_PT * scale + extra;
    let (mut x0, mut y0, mut x1, mut y1) = (pad, pad, w - pad, h - pad);
    if style.shape == Shape::Ellipse {
        // Largest axis-aligned rectangle inside the ellipse: inset by (1 - 1/sqrt 2) / 2 per side.
        let (ix, iy) = ((w * 0.146).max(pad), (h * 0.146).max(pad));
        (x0, y0, x1, y1) = (ix, iy, w - ix, h - iy);
    }
    (x0, y0, x1.max(x0 + 1.0), y1.max(y0 + 1.0))
}

/// Renders the stamp of `style` with `data` for a box of `w_pt` x `h_pt` points at `scale`
/// pixels per point.
pub fn render(style: &Style, data: &StampData, w_pt: f32, h_pt: f32, scale: f32) -> Rendered {
    let width = (w_pt * scale).round().max(1.0) as u32;
    let height = (h_pt * scale).round().max(1.0) as u32;
    let mut pm = Pixmap::new(width, height).expect("non-zero size");
    let (w, h) = (width as f32, height as f32);
    let id = Transform::identity();

    // Background and border.
    let border_px = style.border.width * scale;
    if let Some(bg) = shape_path(style.shape, w, h, border_px / 2.0, scale) {
        if style.palette.background_opacity > 0.0 {
            pm.fill_path(&bg, &paint(style.palette.background, style.palette.background_opacity), FillRule::Winding, id, None);
        }
        if border_px > 0.0 {
            let mut stroke = Stroke { width: border_px, ..Stroke::default() };
            if style.border.style == BorderStyle::Dashed {
                stroke.dash = StrokeDash::new(vec![border_px * 4.0, border_px * 2.5], 0.0);
            }
            let ink = paint(style.palette.border, 1.0);
            pm.stroke_path(&bg, &ink, &stroke, id, None);
            if style.border.style == BorderStyle::Double {
                if let Some(inner) = shape_path(style.shape, w, h, border_px * 2.5, scale) {
                    let thin = Stroke { width: border_px * 0.6, ..Stroke::default() };
                    pm.stroke_path(&inner, &ink, &thin, id, None);
                }
            }
        }
    }

    // Text.
    let lines: Vec<Line> = style.lines(data);
    let f = fonts_for(style.font.family);
    let (x0, y0, x1, y1) = content_box(style, w, h, scale);
    let (avail_w, avail_h) = (x1 - x0, y1 - y0);
    let units: f32 = lines.iter().map(|l| l.scale).sum::<f32>() * LEADING;
    let base = match style.font.size {
        Some(pt) => pt * scale,
        None => (avail_h / units.max(0.01)).min(MAX_AUTO_PT * scale),
    };
    let mut clipped = style.font.size.is_some() && base * units > avail_h + 0.5;

    let mut pb = PathBuilder::new();
    let block = base * units;
    let mut y = y0 + (avail_h - block).max(0.0) / 2.0;
    for line in &lines {
        let font = if line.bold { &f.bold } else { &f.regular };
        let slot = base * line.scale * LEADING;
        let mut px = base * line.scale;
        let tw = text_width(font, px, &line.text);
        if tw > avail_w {
            if style.font.size.is_some() {
                clipped = true;
            } else {
                px *= avail_w / tw;
            }
        }
        let tw = text_width(font, px, &line.text).min(avail_w);
        let sf = font.as_scaled(PxScale::from(px));
        let baseline = y + (slot + sf.ascent() + sf.descent()) / 2.0;
        let mut x = match style.font.align {
            Align::Left => x0,
            Align::Center => x0 + (avail_w - tw) / 2.0,
            Align::Right => x1 - tw,
        };
        let mut prev = None;
        for c in line.text.chars() {
            let gid = sf.glyph_id(c);
            if let Some(p) = prev {
                x += sf.kern(p, gid);
            }
            push_glyph(&mut pb, font, gid, px, x, baseline);
            x += sf.h_advance(gid);
            prev = Some(gid);
        }
        y += slot;
    }
    if let Some(text) = pb.finish() {
        // Text never escapes the content box (relevant for a fixed size that does not fit).
        let mut mask = tiny_skia::Mask::new(width, height);
        if let (Some(m), Some(r)) = (mask.as_mut(), Rect::from_ltrb(x0, y0, x1, y1)) {
            m.fill_path(&PathBuilder::from_rect(r), FillRule::Winding, true, id);
        }
        pm.fill_path(&text, &paint(style.palette.text, 1.0), FillRule::Winding, id, mask.as_ref());
    }

    let rgba = pm
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect();
    Rendered { width, height, rgba, clipped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::style::builtins;

    fn data(name: &str) -> StampData {
        StampData {
            name: name.into(),
            issuer: "CA".into(),
            reason: "Approved".into(),
            location: "Sofia".into(),
            contact: String::new(),
            time: chrono::Local::now(),
        }
    }

    fn alpha_at(r: &Rendered, x: u32, y: u32) -> u8 {
        r.rgba[((y * r.width + x) * 4 + 3) as usize]
    }

    #[test]
    fn every_builtin_renders_text_inside_the_image() {
        for s in builtins() {
            let r = render(&s, &data("Николай Димчев"), s.size.w, s.size.h, 2.0);
            assert_eq!(r.rgba.len(), (r.width * r.height * 4) as usize);
            let inked = r.rgba.chunks_exact(4).filter(|p| p[3] > 0).count();
            assert!(inked > 200, "{}: almost empty", s.name);
            assert!(!r.clipped, "{}", s.name);
        }
    }

    #[test]
    fn shapes_differ_at_the_corners() {
        let mut s = builtins().remove(0);
        s.palette.background_opacity = 1.0;
        s.shape = Shape::Rect;
        let rect = render(&s, &data("A"), 100.0, 50.0, 2.0);
        s.shape = Shape::Ellipse;
        let ellipse = render(&s, &data("A"), 100.0, 50.0, 2.0);
        s.shape = Shape::None;
        let none = render(&s, &data("A"), 100.0, 50.0, 2.0);
        assert_eq!(alpha_at(&rect, 2, 2), 255);
        assert_eq!(alpha_at(&ellipse, 2, 2), 0);
        assert_eq!(alpha_at(&ellipse, 100, 50), 255);
        assert_eq!(alpha_at(&none, 100, 2), 0);
    }

    #[test]
    fn fixed_size_that_does_not_fit_is_reported() {
        let mut s = builtins().remove(0);
        s.font.size = Some(30.0);
        assert!(render(&s, &data("A very long signer name"), 120.0, 40.0, 2.0).clipped);
    }
}
