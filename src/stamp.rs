//! Rasterizes the visible signature stamp from a [`Style`] into an RGBA image.
//!
//! Shapes, borders and backgrounds are drawn with `tiny-skia`; text is converted from glyph
//! outlines (`ab_glyph`) into paths, so any Unicode (incl. Cyrillic) works without embedding
//! fonts into the PDF, and glyphs can be transformed freely.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use ab_glyph::{Font, FontVec, GlyphId, OutlineCurve, PxScale, ScaleFont};
use tiny_skia::{FillRule, FilterQuality, Paint, Path, PathBuilder, Pixmap, PixmapPaint, Rect, Stroke, StrokeDash, Transform};

use crate::fonts;
use crate::image_src;
use crate::style::{Align, BorderStyle, FontFamily, ImagePosition, Line, Rgb, Shape, StampData, Style, StyleImage};

/// Gap between the picture and the text, in points.
const IMAGE_GAP_PT: f32 = 3.0;

/// The style's picture decoded, background-removed and trimmed, as a premultiplied pixmap.
/// Cached by content and threshold, because rendering happens for every preview frame.
fn processed(img: &StyleImage) -> Option<Arc<Pixmap>> {
    use std::hash::{Hash, Hasher};
    static CACHE: OnceLock<Mutex<HashMap<(u64, u32), Option<Arc<Pixmap>>>>> = OnceLock::new();
    if img.is_empty() {
        return None;
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    img.png_base64.hash(&mut h);
    let key = (h.finish(), img.remove_background.map_or(0, f32::to_bits));
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return hit.clone();
    }
    let result = image_src::from_png_base64(&img.png_base64).ok().and_then(|mut r| {
        if let Some(t) = img.remove_background {
            image_src::remove_background(&mut r, t);
        }
        let r = image_src::trim(&r);
        let mut pm = Pixmap::new(r.width, r.height)?;
        for (dst, src) in pm.pixels_mut().iter_mut().zip(r.rgba.chunks_exact(4)) {
            *dst = tiny_skia::ColorU8::from_rgba(src[0], src[1], src[2], src[3]).premultiply();
        }
        Some(Arc::new(pm))
    });
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() > 32 {
        map.clear();
    }
    map.insert(key, result.clone());
    result
}

/// Size of the processed (background-removed, trimmed) picture.
pub fn picture_size(img: &StyleImage) -> Option<(u32, u32)> {
    processed(img).map(|p| (p.width(), p.height()))
}

/// Draws `pic` fitted (aspect kept) and centred into the box.
fn draw_fitted(pm: &mut Pixmap, pic: &Pixmap, x: f32, y: f32, w: f32, h: f32, opacity: f32) {
    let (pw, ph) = (pic.width() as f32, pic.height() as f32);
    let s = (w / pw).min(h / ph);
    let (dw, dh) = (pw * s, ph * s);
    let t = Transform::from_row(s, 0.0, 0.0, s, x + (w - dw) / 2.0, y + (h - dh) / 2.0);
    let paint = PixmapPaint { opacity: opacity.clamp(0.0, 1.0), quality: FilterQuality::Bicubic, ..PixmapPaint::default() };
    pm.draw_pixmap(0, 0, pic.as_ref(), &paint, t, None);
}

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
        Shape::Ellipse | Shape::Seal => PathBuilder::from_oval(Rect::from_ltrb(x0, y0, x1, y1)?),
        Shape::None => None,
    }
}

/// Appends the outline of one glyph to `pb`. `place` maps glyph-local pixel coordinates
/// (origin on the baseline at the glyph start, y down) to image pixels.
fn push_glyph(pb: &mut PathBuilder, font: &FontVec, id: GlyphId, px: f32, place: &dyn Fn(f32, f32) -> (f32, f32)) {
    let Some(outline) = font.outline(id) else { return };
    let sf = font.as_scaled(PxScale::from(px));
    let (sx, sy) = (sf.h_scale_factor(), sf.v_scale_factor());
    let map = |p: ab_glyph::Point| place(p.x * sx, -p.y * sy);
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
    if style.shape == Shape::Seal {
        render_seal(&mut pm, style, data, scale);
        return finish(pm, false);
    }
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
    let (mut x0, mut y0, mut x1, y1) = content_box(style, w, h, scale);

    // Picture: takes a part of the content box (or sits behind the text).
    if let Some((img, pic)) = style.image.as_ref().and_then(|i| processed(i).map(|p| (i, p))) {
        let (cw, ch) = (x1 - x0, y1 - y0);
        let aspect = pic.width() as f32 / pic.height() as f32;
        let gap = IMAGE_GAP_PT * scale;
        match img.position {
            ImagePosition::Left | ImagePosition::Right => {
                let iw = (cw * 0.42).min(ch * aspect);
                if img.position == ImagePosition::Left {
                    draw_fitted(&mut pm, &pic, x0, y0, iw, ch, img.opacity);
                    x0 += iw + gap;
                } else {
                    draw_fitted(&mut pm, &pic, x1 - iw, y0, iw, ch, img.opacity);
                    x1 -= iw + gap;
                }
            }
            ImagePosition::Top => {
                let ih = (ch * 0.45).min(cw / aspect);
                draw_fitted(&mut pm, &pic, x0, y0, cw, ih, img.opacity);
                y0 += ih + gap;
            }
            ImagePosition::Background => draw_fitted(&mut pm, &pic, x0, y0, cw, ch, img.opacity),
        }
        x1 = x1.max(x0 + 1.0);
        y0 = y0.min(y1 - 1.0);
    }
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
            let gx = x;
            push_glyph(&mut pb, font, gid, px, &|lx, ly| (gx + lx, baseline + ly));
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

    finish(pm, clipped)
}

fn finish(pm: Pixmap, clipped: bool) -> Rendered {
    let rgba = pm
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect();
    Rendered { width: pm.width(), height: pm.height(), rgba, clipped }
}

/// Largest angle (radians) one arc text may span.
const ARC_MAX: f32 = std::f32::consts::PI * 0.82;

/// Font size (px) at which `text` spans at most `max_angle` on a circle of radius `radius`.
fn fit_arc_px(font: &FontVec, text: &str, px: f32, radius: f32, max_angle: f32) -> f32 {
    let w = text_width(font, px, text);
    if w <= 0.0 || w / radius <= max_angle { px } else { px * max_angle * radius / w }
}

/// Text along an arc of radius `radius` around (`cx`, `cy`), centred at the top (`top`) or the
/// bottom; glyphs stay upright and read left to right in both cases.
fn push_arc_text(pb: &mut PathBuilder, font: &FontVec, text: &str, px: f32, cx: f32, cy: f32, radius: f32, top: bool) {
    let sf = font.as_scaled(PxScale::from(px));
    let total = text_width(font, px, text);
    let mut s = 0.0;
    let mut prev = None;
    for c in text.chars() {
        let gid = sf.glyph_id(c);
        if let Some(p) = prev {
            s += sf.kern(p, gid);
        }
        let adv = sf.h_advance(gid);
        let mid = s + adv / 2.0 - total / 2.0;
        // Top: clockwise from the left; bottom: counter-clockwise from the left.
        let theta = if top { -std::f32::consts::FRAC_PI_2 + mid / radius } else { std::f32::consts::FRAC_PI_2 - mid / radius };
        let rot = if top { theta + std::f32::consts::FRAC_PI_2 } else { theta - std::f32::consts::FRAC_PI_2 };
        let (px0, py0) = (cx + radius * theta.cos(), cy + radius * theta.sin());
        let (sin, cos) = rot.sin_cos();
        let half = adv / 2.0;
        push_glyph(pb, font, gid, px, &|lx, ly| {
            let (x, y) = (lx - half, ly);
            (px0 + x * cos - y * sin, py0 + x * sin + y * cos)
        });
        s += adv;
        prev = Some(gid);
    }
}

/// Round seal: outer ring with text along the top and bottom arcs, dots between them, and the
/// picture or a check mark in the centre.
fn render_seal(pm: &mut Pixmap, style: &Style, data: &StampData, scale: f32) {
    let id = Transform::identity();
    let (w, h) = (pm.width() as f32, pm.height() as f32);
    let side = w.min(h);
    let (cx, cy) = (w / 2.0, h / 2.0);
    let border = style.border.width * scale;
    let outer = side / 2.0 - border.max(1.0) / 2.0;
    let ring = outer * 0.26;
    let inner = outer - ring;
    let circle = |r: f32| PathBuilder::from_circle(cx, cy, r.max(0.5));

    if style.palette.background_opacity > 0.0 {
        if let Some(c) = circle(outer) {
            pm.fill_path(&c, &paint(style.palette.background, style.palette.background_opacity), FillRule::Winding, id, None);
        }
    }
    let ink = paint(style.palette.border, 1.0);
    let double = style.border.style == BorderStyle::Double;
    if border > 0.0 {
        let mut stroke = Stroke { width: border, ..Stroke::default() };
        if style.border.style == BorderStyle::Dashed {
            stroke.dash = StrokeDash::new(vec![border * 4.0, border * 2.5], 0.0);
        }
        if let Some(c) = circle(outer) {
            pm.stroke_path(&c, &ink, &stroke, id, None);
        }
        let thin = Stroke { width: (border * 0.6).max(0.8), ..Stroke::default() };
        if double {
            if let Some(c) = circle(outer - border * 2.2) {
                pm.stroke_path(&c, &ink, &thin, id, None);
            }
        }
        if let Some(c) = circle(inner) {
            pm.stroke_path(&c, &ink, &thin, id, None);
        }
    }

    // Arc texts in the middle of the ring.
    let f = fonts_for(style.font.family);
    let (top, bottom) = style.seal_texts(data).unwrap_or_default();
    let mid = (outer - if double { border * 2.2 } else { 0.0 } + inner) / 2.0;
    let base_px = ring * 0.5;
    let cap = |px: f32| px * 0.36;
    let mut pb = PathBuilder::new();
    let top_px = fit_arc_px(&f.bold, &top, base_px, mid, ARC_MAX);
    push_arc_text(&mut pb, &f.bold, &top, top_px, cx, cy, mid - cap(top_px), true);
    let bottom_px = fit_arc_px(&f.regular, &bottom, base_px, mid, ARC_MAX);
    push_arc_text(&mut pb, &f.regular, &bottom, bottom_px, cx, cy, mid + cap(bottom_px), false);
    let text_ink = paint(style.palette.text, 1.0);
    if let Some(p) = pb.finish() {
        pm.fill_path(&p, &text_ink, FillRule::Winding, id, None);
    }
    // Dots separating the two arcs.
    for x in [cx - mid, cx + mid] {
        if let Some(d) = PathBuilder::from_circle(x, cy, ring * 0.08) {
            pm.fill_path(&d, &text_ink, FillRule::Winding, id, None);
        }
    }

    // Centre: picture or check mark.
    let box_side = inner * 1.25;
    let (bx, by) = (cx - box_side / 2.0, cy - box_side / 2.0);
    if let Some((img, pic)) = style.image.as_ref().and_then(|i| processed(i).map(|p| (i, p))) {
        draw_fitted(pm, &pic, bx, by, box_side, box_side, img.opacity);
    } else if style.seal.as_ref().is_some_and(|s| s.check) {
        let mut pb = PathBuilder::new();
        pb.move_to(cx - inner * 0.42, cy + inner * 0.02);
        pb.line_to(cx - inner * 0.12, cy + inner * 0.32);
        pb.line_to(cx + inner * 0.46, cy - inner * 0.3);
        if let Some(p) = pb.finish() {
            let stroke = Stroke {
                width: inner * 0.14,
                line_cap: tiny_skia::LineCap::Round,
                line_join: tiny_skia::LineJoin::Round,
                ..Stroke::default()
            };
            pm.stroke_path(&p, &text_ink, &stroke, id, None);
        }
    }
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
    fn picture_is_drawn_and_text_moves_aside() {
        let mut s = builtins().into_iter().find(|s| s.id == "builtin:handwritten").unwrap();
        let red = image_src::Raster { width: 20, height: 20, rgba: [230, 0, 0, 255].repeat(400) };
        let img = s.image.as_mut().unwrap();
        img.png_base64 = image_src::to_png_base64(&red).unwrap();
        img.remove_background = None;
        let out = render(&s, &data("A"), 200.0, 60.0, 2.0);
        let is_red = |p: &[u8]| p[0] > 200 && p[1] < 60 && p[3] > 200;
        let w = out.width as usize;
        let (mut left, mut right) = (0, 0);
        for (i, p) in out.rgba.chunks_exact(4).enumerate() {
            if is_red(p) {
                if i % w < w / 2 { left += 1 } else { right += 1 }
            }
        }
        assert!(left > 1000, "picture on the left");
        assert_eq!(right, 0, "nothing red on the right");
    }

    #[test]
    fn seal_is_round_with_text_on_the_ring_and_a_check() {
        let s = builtins().into_iter().find(|s| s.shape == Shape::Seal).unwrap();
        let r = render(&s, &data("Николай Пламенов Димчев"), 110.0, 110.0, 3.0);
        let (w, h) = (r.width, r.height);
        assert_eq!(alpha_at(&r, 2, 2), 0, "corner outside the circle");
        let centre = (h / 2 - 10..h / 2 + 10).flat_map(|y| (w / 2 - 20..w / 2 + 20).map(move |x| (x, y))).filter(|&(x, y)| alpha_at(&r, x, y) > 128).count();
        assert!(centre > 20, "check mark in the centre");
        let ring_y = (h as f32 * 0.13) as u32;
        let inked = (0..w).filter(|&x| alpha_at(&r, x, ring_y) > 128).count();
        assert!(inked > 10, "top arc text present");
    }

    #[test]
    fn long_arc_text_is_shrunk_to_fit() {
        let f = fonts_for(FontFamily::Sans);
        let long = "DIGITALLY SIGNED BY • A VERY LONG SIGNER NAME WITH SEVERAL WORDS";
        let px = fit_arc_px(&f.bold, long, 30.0, 100.0, ARC_MAX);
        assert!(px < 30.0);
        assert!(text_width(&f.bold, px, long) / 100.0 <= ARC_MAX + 1e-3);
        assert_eq!(fit_arc_px(&f.bold, "OK", 30.0, 100.0, ARC_MAX), 30.0);
    }

    #[test]
    fn fixed_size_that_does_not_fit_is_reported() {
        let mut s = builtins().remove(0);
        s.font.size = Some(30.0);
        assert!(render(&s, &data("A very long signer name"), 120.0, 40.0, 2.0).clipped);
    }
}
