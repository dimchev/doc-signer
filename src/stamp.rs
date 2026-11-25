//! Rasterizes the visible signature stamp. Text is rendered to an alpha mask so any
//! Unicode (incl. Cyrillic) works without embedding fonts into the PDF.

use std::sync::OnceLock;

use ab_glyph::{Font, FontVec, PxScale, ScaleFont, point};

use crate::i18n::t;

pub const INK: [u8; 3] = [0x1a, 0x3e, 0x8c];

struct Fonts {
    regular: FontVec,
    bold: FontVec,
}

fn load(names: &[&str]) -> Option<FontVec> {
    let bytes = {
        #[cfg(windows)]
        {
            let dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
            names.iter().find_map(|n| std::fs::read(format!("{dir}\\Fonts\\{n}"))).ok()
        }
        #[cfg(not(windows))]
        {
            // Debian/Ubuntu keep fonts under truetype/, Arch (and friends) directly under /usr/share/fonts.
            let roots = ["/usr/share/fonts/truetype", "/usr/share/fonts", "/usr/local/share/fonts"];
            let fams = ["dejavu", "liberation", "noto"];
            let mut candidates = Vec::new();
            for n in names {
                for r in roots {
                    candidates.push(format!("{r}/{n}"));
                    for f in fams {
                        candidates.push(format!("{r}/{f}/{n}"));
                    }
                }
            }
            candidates.iter().find_map(|p| std::fs::read(p).ok())
        }
    }?;
    FontVec::try_from_vec(bytes).ok()
}

fn fonts() -> Option<&'static Fonts> {
    static F: OnceLock<Option<Fonts>> = OnceLock::new();
    F.get_or_init(|| {
        #[cfg(windows)]
        {
            let regular = load(&["arial.ttf", "segoeui.ttf", "tahoma.ttf"])?;
            let bold = load(&["arialbd.ttf", "segoeuib.ttf"]).unwrap_or_else(|| load(&["arial.ttf", "segoeui.ttf"]).unwrap());
            Some(Fonts { regular, bold })
        }
        #[cfg(not(windows))]
        {
            let regular = load(&["DejaVuSans.ttf", "NotoSans-Regular.ttf", "LiberationSans-Regular.ttf"])?;
            let bold = load(&["DejaVuSans-Bold.ttf", "NotoSans-Bold.ttf", "LiberationSans-Bold.ttf"])
                .unwrap_or_else(|| load(&["DejaVuSans.ttf", "NotoSans-Regular.ttf", "LiberationSans-Regular.ttf"]).unwrap());
            Some(Fonts { regular, bold })
        }
    })
    .as_ref()
}

pub struct Line {
    pub text: String,
    pub big: bool,
}

pub fn lines(name: &str, date: &str, reason: &str, location: &str) -> Vec<Line> {
    let mut v = vec![
        Line { text: t().stamp_signed_by.into(), big: false },
        Line { text: name.into(), big: true },
        Line { text: format!("{}: {date}", t().stamp_date), big: false },
    ];
    if !reason.trim().is_empty() {
        v.push(Line { text: format!("{}: {}", t().reason, reason.trim()), big: false });
    }
    if !location.trim().is_empty() {
        v.push(Line { text: format!("{}: {}", t().location, location.trim()), big: false });
    }
    v
}

pub struct Mask {
    pub width: u32,
    pub height: u32,
    pub alpha: Vec<u8>,
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

/// Renders the stamp for a box of `w_pt` x `h_pt` points at `scale` pixels per point.
pub fn render(lines: &[Line], w_pt: f32, h_pt: f32, scale: f32) -> Mask {
    let width = (w_pt * scale).round().max(1.0) as u32;
    let height = (h_pt * scale).round().max(1.0) as u32;
    let mut alpha = vec![0u8; (width * height) as usize];
    let Some(f) = fonts() else {
        return Mask { width, height, alpha };
    };

    let pad = 4.0 * scale;
    let avail_w = width as f32 - 2.0 * pad;
    let avail_h = height as f32 - 2.0 * pad;
    const BIG: f32 = 1.45;
    const LEADING: f32 = 1.18;
    let units: f32 = lines.iter().map(|l| if l.big { BIG } else { 1.0 }).sum::<f32>() * LEADING;
    let base = (avail_h / units).min(9.0 * scale);

    let sizes: Vec<f32> = lines
        .iter()
        .map(|l| {
            let font = if l.big { &f.bold } else { &f.regular };
            let px = base * if l.big { BIG } else { 1.0 };
            let tw = text_width(font, px, &l.text);
            if tw > avail_w { px * avail_w / tw } else { px }
        })
        .collect();
    let block: f32 = lines.iter().map(|l| base * if l.big { BIG } else { 1.0 } * LEADING).sum();
    let mut y = pad + (avail_h - block).max(0.0) / 2.0;

    for (line, &px) in lines.iter().zip(&sizes) {
        let slot = base * if line.big { BIG } else { 1.0 } * LEADING;
        let font = if line.big { &f.bold } else { &f.regular };
        let sf = font.as_scaled(PxScale::from(px));
        let baseline = y + (slot + sf.ascent() + sf.descent()) / 2.0;
        let mut x = pad;
        let mut prev = None;
        for c in line.text.chars() {
            let gid = sf.glyph_id(c);
            if let Some(p) = prev {
                x += sf.kern(p, gid);
            }
            let glyph = gid.with_scale_and_position(PxScale::from(px), point(x, baseline));
            x += sf.h_advance(gid);
            prev = Some(gid);
            if let Some(og) = font.outline_glyph(glyph) {
                let b = og.px_bounds();
                og.draw(|gx, gy, cov| {
                    let px_x = b.min.x as i32 + gx as i32;
                    let px_y = b.min.y as i32 + gy as i32;
                    if px_x >= 0 && px_y >= 0 && (px_x as u32) < width && (px_y as u32) < height {
                        let i = (px_y as u32 * width + px_x as u32) as usize;
                        alpha[i] = alpha[i].max((cov.clamp(0.0, 1.0) * 255.0) as u8);
                    }
                });
            }
        }
        y += slot;
    }
    Mask { width, height, alpha }
}
