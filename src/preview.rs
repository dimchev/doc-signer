//! Optional page rendering via pdfium.dll (if present next to the exe).

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
