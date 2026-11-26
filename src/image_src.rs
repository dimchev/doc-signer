//! Images for stamp styles: loading (PNG / JPEG / SVG / PDF page), downscaling, white-background
//! removal, trimming and the base64-PNG form stored in style files.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Longest side of a stored image, in pixels.
pub const MAX_SIDE: u32 = 1500;

/// Unpremultiplied RGBA image.
#[derive(Clone, Debug, PartialEq)]
pub struct Raster {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

impl Raster {
    pub fn is_opaque(&self) -> bool {
        self.rgba.chunks_exact(4).all(|p| p[3] == 255)
    }
}

fn decode(bytes: &[u8]) -> Result<Raster> {
    let img = image::load_from_memory(bytes)?.to_rgba8();
    Ok(Raster { width: img.width(), height: img.height(), rgba: img.into_raw() })
}

fn svg(bytes: &[u8]) -> Result<Raster> {
    use resvg::{tiny_skia, usvg};
    let tree = usvg::Tree::from_data(bytes, &usvg::Options::default())?;
    let size = tree.size();
    let scale = (MAX_SIDE as f32 / size.width().max(size.height())).max(0.01);
    let (w, h) = (((size.width() * scale).ceil() as u32).max(1), ((size.height() * scale).ceil() as u32).max(1));
    let mut pm = tiny_skia::Pixmap::new(w, h).ok_or_else(|| anyhow!("SVG size"))?;
    resvg::render(&tree, tiny_skia::Transform::from_scale(scale, scale), &mut pm.as_mut());
    let rgba = pm
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect();
    Ok(Raster { width: w, height: h, rgba })
}

/// Loads an image file; `.pdf` is rendered through `render_pdf` (first page).
pub fn load_file(path: &Path, render_pdf: &dyn Fn(&Path) -> Result<Raster>) -> Result<Raster> {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let raster = match ext.as_str() {
        "pdf" => render_pdf(path)?,
        "svg" => svg(&std::fs::read(path)?)?,
        _ => decode(&std::fs::read(path)?)?,
    };
    Ok(downscale(raster, MAX_SIDE))
}

pub fn downscale(r: Raster, max_side: u32) -> Raster {
    let longest = r.width.max(r.height);
    if longest <= max_side {
        return r;
    }
    let f = max_side as f32 / longest as f32;
    let (w, h) = (((r.width as f32 * f).round() as u32).max(1), ((r.height as f32 * f).round() as u32).max(1));
    let img = image::RgbaImage::from_raw(r.width, r.height, r.rgba).expect("buffer matches size");
    let out = image::imageops::resize(&img, w, h, image::imageops::FilterType::Triangle);
    Raster { width: w, height: h, rgba: out.into_raw() }
}

/// Makes near-white pixels transparent. Pixels with luminance >= `threshold` (0..1) disappear;
/// a soft ramp below it keeps anti-aliased pen edges smooth.
pub fn remove_background(r: &mut Raster, threshold: f32) {
    const RAMP: f32 = 0.15;
    for p in r.rgba.chunks_exact_mut(4) {
        let lum = (0.2126 * p[0] as f32 + 0.7152 * p[1] as f32 + 0.0722 * p[2] as f32) / 255.0;
        let keep = ((threshold - lum) / RAMP).clamp(0.0, 1.0);
        p[3] = (p[3] as f32 * keep).round() as u8;
    }
}

/// Crops to the visible pixels (alpha > 8) plus a small margin; a fully transparent image stays 1×1.
pub fn trim(r: &Raster) -> Raster {
    let (w, h) = (r.width as usize, r.height as usize);
    let (mut x0, mut y0, mut x1, mut y1) = (w, h, 0usize, 0usize);
    for y in 0..h {
        for x in 0..w {
            if r.rgba[(y * w + x) * 4 + 3] > 8 {
                x0 = x0.min(x);
                y0 = y0.min(y);
                x1 = x1.max(x);
                y1 = y1.max(y);
            }
        }
    }
    if x0 > x1 {
        return Raster { width: 1, height: 1, rgba: vec![0; 4] };
    }
    const MARGIN: usize = 2;
    let (x0, y0) = (x0.saturating_sub(MARGIN), y0.saturating_sub(MARGIN));
    let (x1, y1) = ((x1 + MARGIN).min(w - 1), (y1 + MARGIN).min(h - 1));
    let (nw, nh) = (x1 - x0 + 1, y1 - y0 + 1);
    let mut rgba = Vec::with_capacity(nw * nh * 4);
    for y in y0..=y1 {
        rgba.extend_from_slice(&r.rgba[(y * w + x0) * 4..(y * w + x1 + 1) * 4]);
    }
    Raster { width: nw as u32, height: nh as u32, rgba }
}

pub fn to_png_base64(r: &Raster) -> Result<String> {
    let mut png = Vec::new();
    image::write_buffer_with_format(
        &mut std::io::Cursor::new(&mut png),
        &r.rgba,
        r.width,
        r.height,
        image::ExtendedColorType::Rgba8,
        image::ImageFormat::Png,
    )?;
    Ok(STANDARD.encode(png))
}

pub fn from_png_base64(s: &str) -> Result<Raster> {
    if s.is_empty() {
        bail!("empty image");
    }
    let bytes = STANDARD.decode(s.trim()).context("base64")?;
    decode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// White canvas with a dark 4×2 block at (3, 5).
    fn scan() -> Raster {
        let (w, h) = (12u32, 10u32);
        let mut rgba = vec![255u8; (w * h * 4) as usize];
        for y in 5..7 {
            for x in 3..7 {
                let i = ((y * w + x) * 4) as usize;
                rgba[i..i + 3].copy_from_slice(&[20, 30, 90]);
            }
        }
        Raster { width: w, height: h, rgba }
    }

    #[test]
    fn white_background_becomes_transparent_and_is_trimmed() {
        let mut r = scan();
        assert!(r.is_opaque());
        remove_background(&mut r, 0.92);
        assert_eq!(r.rgba[3], 0, "white corner is transparent");
        let t = trim(&r);
        assert_eq!((t.width, t.height), (4 + 4, 2 + 4), "block plus a 2 px margin");
        assert!(t.rgba.chunks_exact(4).any(|p| p[3] == 255 && p[0] == 20));
    }

    #[test]
    fn png_base64_round_trip_and_downscale() {
        let r = scan();
        let back = from_png_base64(&to_png_base64(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        let big = Raster { width: 3000, height: 1000, rgba: vec![0; 3000 * 1000 * 4] };
        let small = downscale(big, MAX_SIDE);
        assert_eq!((small.width, small.height), (1500, 500));
    }

    #[test]
    fn svg_is_rasterized_with_transparency() {
        let svg_src = br##"<svg xmlns="http://www.w3.org/2000/svg" width="100" height="50"><rect x="10" y="10" width="30" height="20" fill="#1a3e8c"/></svg>"##;
        let r = svg(svg_src).unwrap();
        assert_eq!(r.width, MAX_SIDE);
        assert_eq!(r.rgba[3], 0, "outside the rect is transparent");
        assert!(r.rgba.chunks_exact(4).any(|p| p[3] == 255 && p[2] == 0x8c));
    }
}
