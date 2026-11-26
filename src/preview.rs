//! Optional page rendering via pdfium (pdfium.dll on Windows, libpdfium.so on Linux, if present next to the exe).

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use eframe::egui::ColorImage;
use pdfium_render::prelude::*;

pub struct Previewer {
    pdfium: Option<Pdfium>,
}

fn candidate_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        v.push(dir);
    }
    if let Ok(cwd) = std::env::current_dir() {
        v.push(cwd);
    }
    v
}

impl Previewer {
    pub fn new() -> Self {
        let pdfium = candidate_dirs()
            .into_iter()
            .find_map(|d| Pdfium::bind_to_library(Pdfium::pdfium_platform_library_name_at_path(&d)).ok())
            .map(Pdfium::new);
        Self { pdfium }
    }

    pub fn available(&self) -> bool {
        self.pdfium.is_some()
    }

    /// First page as unpremultiplied RGBA, longest side `max_side` (for importing a PDF graphic).
    pub fn render_raster(&self, path: &Path, max_side: u32) -> Result<crate::image_src::Raster> {
        let pdfium = self.pdfium.as_ref().ok_or_else(|| anyhow!("{}", crate::i18n::t().no_pdfium))?;
        let doc = pdfium.load_pdf_from_file(path, None)?;
        let page = doc.pages().get(0)?;
        let (w, h) = (page.width().value, page.height().value);
        let cfg = if w >= h {
            PdfRenderConfig::new().set_target_width(max_side as i32)
        } else {
            PdfRenderConfig::new().set_target_height(max_side as i32)
        };
        let img = page.render_with_config(&cfg)?.as_image()?.into_rgba8();
        Ok(crate::image_src::Raster { width: img.width(), height: img.height(), rgba: img.into_raw() })
    }

    /// First page of an in-memory PDF on a transparent background, longest side `max_side`.
    pub fn render_bytes_raster(&self, bytes: &[u8], max_side: u32) -> Result<crate::image_src::Raster> {
        let pdfium = self.pdfium.as_ref().ok_or_else(|| anyhow!("{}", crate::i18n::t().no_pdfium))?;
        let doc = pdfium.load_pdf_from_byte_slice(bytes, None)?;
        let page = doc.pages().get(0)?;
        let (w, h) = (page.width().value, page.height().value);
        let cfg = if w >= h { PdfRenderConfig::new().set_target_width(max_side as i32) } else { PdfRenderConfig::new().set_target_height(max_side as i32) };
        let img = page.render_with_config(&cfg.set_clear_color(PdfColor::new(255, 255, 255, 0)))?.as_image()?.into_rgba8();
        Ok(crate::image_src::Raster { width: img.width(), height: img.height(), rgba: img.into_raw() })
    }

    pub fn render(&self, path: &Path, page: usize, width_px: i32) -> Result<ColorImage> {
        let pdfium = self.pdfium.as_ref().ok_or_else(|| anyhow!("{}", crate::i18n::t().no_pdfium))?;
        let doc = pdfium.load_pdf_from_file(path, None)?;
        let page = doc.pages().get(page as _)?;
        let bitmap = page.render_with_config(&PdfRenderConfig::new().set_target_width(width_px))?;
        let img = bitmap.as_image()?.into_rgba8();
        let size = [img.width() as usize, img.height() as usize];
        Ok(ColorImage::from_rgba_unmultiplied(size, img.as_raw()))
    }
}



#[cfg(test)]
mod tests {
    /// Needs pdfium (pdfium.dll / libpdfium.so) next to the test binary or in the working directory.
    #[test]
    fn renders_a_signature_appearance_on_a_transparent_background() {
        let p = super::Previewer::new();
        if !p.available() {
            eprintln!("SKIPPED renders_a_signature_appearance_on_a_transparent_background: pdfium not found");
            return;
        }
        let bytes = include_bytes!("../tests/fixtures/signed-by-pyhanko.pdf");
        let a = crate::pdf::signature_appearances(bytes).unwrap().remove(0);
        let r = p.render_bytes_raster(&a.pdf, 440).unwrap();
        assert_eq!(r.width, 440);
        let alpha = |x: u32, y: u32| r.rgba[((y * r.width + x) * 4 + 3) as usize];
        assert_eq!(alpha(r.width / 2, r.height / 8), 0, "empty area inside the frame is transparent");
        assert!(r.rgba.chunks_exact(4).filter(|px| px[3] > 200).count() > 500, "text and frame are drawn");
    }
}