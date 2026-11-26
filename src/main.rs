#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod asic;
mod cades;
mod certs;
mod i18n;
mod image_src;
mod cms;
mod fonts;
mod pdf;
mod preview;
mod settings;
mod stamp;
mod style;
mod style_ui;
mod tsa;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};

use chrono::Local;
use eframe::egui::{self, Color32, RichText, Sense, Stroke, StrokeKind, TextureHandle, TextureOptions, Vec2, pos2, vec2};

use certs::CertInfo;
use i18n::t;
use pdf::PdfInfo;

const MARGIN: f32 = 36.0;

fn main() -> eframe::Result {
    i18n::set(i18n::initial());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(t().window_title)
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([1000.0, 620.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native("Doc Signer", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

#[derive(Clone)]
enum Status {
    Ready,
    Queued,
    Signed(PathBuf),
    Failed(String),
}

#[derive(Clone, Copy)]
struct Placement {
    page: usize,
    /// Top-left corner in display points.
    x: f32,
    y: f32,
}

struct Doc {
    path: PathBuf,
    info: Result<PdfInfo, String>,
    checked: bool,
    status: Status,
    placement: Option<Placement>,
    /// Stamp size in points set by resizing on the page; `None` = the style's default size.
    size: Option<Vec2>,
    /// Style id for this document only; `None` = the selected style.
    style: Option<String>,
    /// PDF (PAdES, visible stamp) or any other file (CAdES `.p7s` / `.p7m`).
    pdf: bool,
    /// File size in bytes (shown for non-PDF files).
    bytes: u64,
}

impl Doc {
    fn name(&self) -> String {
        self.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Output {
    Suffix,
    Overwrite,
}

enum Level {
    Info,
    Ok,
    Err,
}

enum JobMsg {
    Done(usize, Result<PathBuf, String>),
    Finished,
}

struct App {
    docs: Vec<Doc>,
    selected: Option<usize>,
    page: usize,

    certs: Vec<CertInfo>,
    cert: Option<usize>,
    show_all_certs: bool,

    reason: String,
    location: String,
    contact: String,
    visible: bool,
    /// Add an RFC 3161 time-stamp (PAdES B-T) from `tsa_url`.
    use_tsa: bool,
    tsa_url: String,
    /// Signature format for non-PDF files.
    cades_format: cades::Format,
    styles: style_ui::StyleUi,
    /// Corner being dragged on the page preview and the fixed opposite corner (page points).
    resizing: Option<(usize, egui::Pos2)>,

    output: Output,
    suffix: String,
    open_folder_after: bool,

    log: Vec<(Level, String)>,
    previewer: preview::Previewer,
    page_tex: Option<(PathBuf, usize, Result<TextureHandle, String>)>,
    job: Option<Receiver<JobMsg>>,
}

impl App {
    fn new(cc: &eframe::CreationContext) -> Self {
        install_fonts(&cc.egui_ctx);
        let mut app = Self {
            docs: Vec::new(),
            selected: None,
            page: 0,
            certs: Vec::new(),
            cert: None,
            show_all_certs: false,
            reason: String::new(),
            location: String::new(),
            contact: String::new(),
            visible: true,
            use_tsa: settings::get("tsa").as_deref() == Some("1"),
            tsa_url: settings::get("tsa_url").filter(|u| !u.trim().is_empty()).unwrap_or_else(|| tsa::DEFAULT_URL.into()),
            cades_format: cades::Format::from_code(settings::get("cades").as_deref().unwrap_or("p7s")),
            styles: style_ui::StyleUi::new(),
            resizing: None,
            output: Output::Suffix,
            suffix: t().default_suffix.into(),
            open_folder_after: false,
            log: Vec::new(),
            previewer: preview::Previewer::new(),
            page_tex: None,
            job: None,
        };
        if !app.previewer.available() {
            app.push(Level::Info, t().pdfium_missing);
        }
        if stamp::uses_builtin_font() {
            app.push(Level::Info, t().stamp_font_fallback);
        }
        app.reload_certs();
        for arg in std::env::args_os().skip(1) {
            app.add_file(PathBuf::from(arg));
        }
        app
    }

    /// Values shown in the stamp preview (the signing thread uses the time of signing).
    fn stamp_data(&self) -> style::StampData {
        let cert = self.current_cert();
        style::StampData {
            name: cert.map(|c| c.subject.clone()).unwrap_or_else(|| t().sample_name.into()),
            issuer: cert.map(|c| c.issuer.clone()).unwrap_or_default(),
            reason: self.reason.clone(),
            location: self.location.clone(),
            contact: self.contact.clone(),
            time: Local::now(),
        }
    }

    fn doc_style(&self, d: &Doc) -> &style::Style {
        d.style.as_deref().and_then(|id| self.styles.get(id)).unwrap_or_else(|| self.styles.current())
    }

    fn doc_size(&self, d: &Doc) -> Vec2 {
        d.size.unwrap_or_else(|| {
            let s = self.doc_style(d);
            vec2(s.size.w, s.size.h)
        })
    }

    fn push(&mut self, level: Level, msg: impl Into<String>) {
        let ts = Local::now().format("%H:%M:%S");
        self.log.push((level, format!("[{ts}] {}", msg.into())));
    }

    fn reload_certs(&mut self) {
        let prev = self.current_cert().map(|c| c.thumbprint.clone());
        match certs::list_certificates() {
            Ok(list) => {
                self.certs = list;
                self.cert = prev
                    .and_then(|t| self.visible_certs().into_iter().find(|&i| self.certs[i].thumbprint == t))
                    .or_else(|| self.visible_certs().first().copied());
                if self.certs.is_empty() {
                    self.push(Level::Err, t().no_certs);
                    #[cfg(not(windows))]
                    self.push(Level::Info, t().no_certs_hint.replace("{d}", &certs::dir().display().to_string()));
                }
            }
            Err(e) => self.push(Level::Err, format!("{}: {e:#}", t().certs_error)),
        }
    }

    fn visible_certs(&self) -> Vec<usize> {
        (0..self.certs.len()).filter(|&i| self.show_all_certs || self.certs[i].is_valid_now()).collect()
    }

    fn current_cert(&self) -> Option<&CertInfo> {
        self.cert.and_then(|i| self.certs.get(i))
    }

    fn add_file(&mut self, path: PathBuf) {
        let is_pdf = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"));
        if self.docs.iter().any(|d| d.path == path) {
            return;
        }
        let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let info = if is_pdf {
            std::fs::read(&path).map_err(|e| e.to_string()).and_then(|b| pdf::inspect(&b).map_err(|e| format!("{e:#}")))
        } else {
            // Any other file is signed as a whole (CAdES); one placeholder page keeps the PDF-only code paths safe.
            std::fs::File::open(&path)
                .map(|_| PdfInfo { pages: vec![pdf::PageGeom { crop: [0.0, 0.0, 595.0, 842.0], rotate: 0 }], signatures: 0 })
                .map_err(|e| e.to_string())
        };
        if let Err(e) = &info {
            self.push(Level::Err, format!("{}: {e}", path.display()));
        }
        let checked = info.is_ok();
        self.docs.push(Doc { path, info, checked, status: Status::Ready, placement: None, size: None, style: None, pdf: is_pdf, bytes });
        if self.selected.is_none() {
            self.select(self.docs.len() - 1);
        }
    }

    fn select(&mut self, idx: usize) {
        self.selected = Some(idx);
        let doc = &self.docs[idx];
        self.page = match (&doc.placement, &doc.info) {
            (Some(p), _) => p.page,
            (None, Ok(info)) if self.visible => info.pages.len() - 1,
            _ => 0,
        };
    }

    fn default_placement(&self, info: &PdfInfo, size: Vec2) -> Placement {
        let page = info.pages.len() - 1;
        let (pw, ph) = info.pages[page].display_size();
        Placement {
            page,
            x: (pw - size.x - MARGIN).max(0.0),
            y: (ph - size.y - MARGIN).max(0.0),
        }
    }

    fn placement_for(&self, doc: &Doc) -> Option<Placement> {
        let info = doc.info.as_ref().ok()?;
        let size = self.doc_size(doc);
        let p = doc.placement.unwrap_or_else(|| self.default_placement(info, size));
        let (pw, ph) = info.pages[p.page].display_size();
        Some(Placement {
            page: p.page,
            x: p.x.clamp(0.0, (pw - size.x).max(0.0)),
            y: p.y.clamp(0.0, (ph - size.y).max(0.0)),
        })
    }

    fn pick_files(&mut self) {
        let dialog = rfd::FileDialog::new().add_filter(t().pdf_filter, &["pdf"]).add_filter(t().all_files, &["*"]).set_title(t().pick_title);
        if let Some(files) = dialog.pick_files() {
            for f in files {
                self.add_file(f);
            }
        }
    }

    /// `file.ext.p7s` / `file.ext.p7m` next to a non-PDF file (never overwriting an existing one).
    fn cades_output_path(&self, src: &Path) -> PathBuf {
        let ext = self.cades_format.extension();
        let name = src.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let dir = src.parent().unwrap_or(Path::new("."));
        let mut p = dir.join(format!("{name}.{ext}"));
        let mut n = 2;
        while p.exists() {
            p = dir.join(format!("{name} ({n}).{ext}"));
            n += 1;
        }
        p
    }

    fn output_path(&self, src: &Path) -> PathBuf {
        if self.output == Output::Overwrite {
            return src.to_path_buf();
        }
        let stem = src.file_stem().unwrap_or_default().to_string_lossy();
        let dir = src.parent().unwrap_or(Path::new("."));
        let mut p = dir.join(format!("{stem}{}.pdf", self.suffix));
        let mut n = 2;
        while p.exists() {
            p = dir.join(format!("{stem}{} ({n}).pdf", self.suffix));
            n += 1;
        }
        p
    }

    fn start_signing(&mut self, ctx: &egui::Context) {
        let Some(cert) = self.current_cert().cloned() else { return };
        let cades_format = self.cades_format;
        let asice = cades_format == cades::Format::Asice;
        let container: Vec<(usize, PathBuf)> = if asice {
            self.docs.iter().enumerate().filter(|(_, d)| d.checked && d.info.is_ok() && !d.pdf).map(|(i, d)| (i, d.path.clone())).collect()
        } else {
            Vec::new()
        };
        let container_dst = container.first().map(|(_, p)| self.cades_output_path(p));
        let tasks: Vec<(usize, PathBuf, PathBuf, Option<(usize, [f32; 4])>, style::Style, bool)> = self
            .docs
            .iter()
            .enumerate()
            .filter(|(_, d)| d.checked && d.info.is_ok() && (d.pdf || !asice))
            .map(|(i, d)| {
                let visible = if self.visible && d.pdf {
                    let size = self.doc_size(d);
                    self.placement_for(d).map(|p| (p.page, [p.x, p.y, size.x, size.y]))
                } else {
                    None
                };
                let dst = if d.pdf { self.output_path(&d.path) } else { self.cades_output_path(&d.path) };
                (i, d.path.clone(), dst, visible, self.doc_style(d).clone(), d.pdf)
            })
            .collect();
        if tasks.is_empty() && container.is_empty() {
            return;
        }
        for i in tasks.iter().map(|t| t.0).chain(container.iter().map(|c| c.0)) {
            self.docs[i].status = Status::Queued;
        }
        let n = tasks.len() + container.len();
        self.push(Level::Info, t().signing_log.replace("{n}", &n.to_string()).replace("{cert}", &cert.subject));

        let (tx, rx) = channel();
        self.job = Some(rx);
        let (reason, location, contact) = (self.reason.clone(), self.location.clone(), self.contact.clone());
        let tsa_url = self.use_tsa.then(|| self.tsa_url.trim().to_string());
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let signer = certs::load_signer(&cert.thumbprint);
            for (idx, src, dst, visible, stamp_style, is_pdf) in tasks {
                let result = (|| -> anyhow::Result<PathBuf> {
                    let signer = signer.as_ref().map_err(|e| anyhow::anyhow!("{e:#}"))?;
                    let input = std::fs::read(&src)?;
                    let ts = |v: &[u8]| tsa::timestamp(tsa_url.as_deref().unwrap_or(tsa::DEFAULT_URL), v).map(|t| t.token);
                    let ts_ref: Option<pdf::Timestamper> = if tsa_url.is_some() { Some(&ts) } else { None };
                    let sign = |d: &[u8]| certs::sign_data(&cert.thumbprint, d, signer.alg);
                    let tmp = PathBuf::from(format!("{}.tmp", dst.display()));
                    if !is_pdf {
                        let out = cades::sign(&input, cades_format, signer, &sign, ts_ref)?;
                        std::fs::write(&tmp, &out)?;
                        std::fs::rename(&tmp, &dst)?;
                        return Ok(dst);
                    }
                    let time = Local::now();
                    let visible = visible.map(|(page, rect)| {
                        let data = style::StampData {
                            name: cert.subject.clone(),
                            issuer: cert.issuer.clone(),
                            reason: reason.clone(),
                            location: location.clone(),
                            contact: contact.clone(),
                            time,
                        };
                        pdf::Visible { page, rect, image: stamp::render(&stamp_style, &data, rect[2], rect[3], 4.0) }
                    });
                    let req = pdf::SignRequest {
                        signer_name: cert.subject.clone(),
                        reason: reason.clone(),
                        location: location.clone(),
                        contact: contact.clone(),
                        time,
                        visible,
                    };
                    let out = pdf::sign_pdf(&input, &req, signer, &sign, ts_ref)?;
                    std::fs::write(&tmp, &out)?;
                    std::fs::rename(&tmp, &dst)?;
                    Ok(dst)
                })();
                let _ = tx.send(JobMsg::Done(idx, result.map_err(|e| format!("{e:#}"))));
                ctx.request_repaint();
            }
            if let Some(dst) = container_dst {
                let result = (|| -> anyhow::Result<PathBuf> {
                    let signer = signer.as_ref().map_err(|e| anyhow::anyhow!("{e:#}"))?;
                    let paths: Vec<&Path> = container.iter().map(|(_, p)| p.as_path()).collect();
                    let mut files = Vec::new();
                    for (name, path) in asic::entry_names(&paths).into_iter().zip(&paths) {
                        files.push((name, std::fs::read(path)?));
                    }
                    let ts = |v: &[u8]| tsa::timestamp(tsa_url.as_deref().unwrap_or(tsa::DEFAULT_URL), v).map(|t| t.token);
                    let ts_ref: Option<pdf::Timestamper> = if tsa_url.is_some() { Some(&ts) } else { None };
                    let out = asic::build(&files, signer, &|d| certs::sign_data(&cert.thumbprint, d, signer.alg), ts_ref)?;
                    let tmp = PathBuf::from(format!("{}.tmp", dst.display()));
                    std::fs::write(&tmp, &out)?;
                    std::fs::rename(&tmp, &dst)?;
                    Ok(dst)
                })();
                let result = result.map_err(|e| format!("{e:#}"));
                for (idx, _) in &container {
                    let _ = tx.send(JobMsg::Done(*idx, result.clone()));
                }
                ctx.request_repaint();
            }
            let _ = tx.send(JobMsg::Finished);
            ctx.request_repaint();
        });
    }

    fn poll_job(&mut self) {
        let Some(rx) = &self.job else { return };
        let msgs: Vec<JobMsg> = rx.try_iter().collect();
        let mut last_ok: Option<PathBuf> = None;
        for m in msgs {
            match m {
                JobMsg::Done(i, Ok(p)) => {
                    self.push(Level::Ok, format!("{}: {}", t().signed_log, p.display()));
                    last_ok = Some(p.clone());
                    if let Some(doc) = self.docs.get_mut(i) {
                        if doc.path == p {
                            if let Ok(info) = std::fs::read(&p).map_err(anyhow::Error::from).and_then(|b| pdf::inspect(&b)) {
                                doc.info = Ok(info);
                            }
                        }
                        doc.status = Status::Signed(p);
                        doc.checked = false;
                    }
                }
                JobMsg::Done(i, Err(e)) => {
                    let name = self.docs.get(i).map(|d| d.name()).unwrap_or_default();
                    self.push(Level::Err, format!("{name}: {e}"));
                    if let Some(doc) = self.docs.get_mut(i) {
                        doc.status = Status::Failed(e);
                    }
                }
                JobMsg::Finished => {
                    self.job = None;
                    self.page_tex = None;
                    if self.open_folder_after {
                        if let Some(p) = &last_ok {
                            reveal(p);
                        }
                    }
                }
            }
        }
    }

    // ---------------- UI ----------------

    fn documents_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(t().docs_heading);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(!self.docs.is_empty() && self.job.is_none(), egui::Button::new(t().clear)).clicked() {
                    self.docs.clear();
                    self.selected = None;
                    self.page_tex = None;
                }
                if ui.button(t().add).on_hover_text("Ctrl+O").clicked() {
                    self.pick_files();
                }
            });
        });
        ui.label(RichText::new(t().drop_hint).weak().small());
        ui.separator();

        if self.docs.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("📄").size(48.0).weak());
                ui.label(RichText::new(t().no_docs).weak());
            });
            return;
        }

        let all_checked = self.docs.iter().filter(|d| d.info.is_ok()).all(|d| d.checked);
        let mut toggle_all = all_checked;
        if ui.checkbox(&mut toggle_all, t().select_all).changed() {
            for d in self.docs.iter_mut().filter(|d| d.info.is_ok()) {
                d.checked = toggle_all;
            }
        }

        let mut remove = None;
        let mut select = None;
        let busy = self.job.is_some();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (i, doc) in self.docs.iter_mut().enumerate() {
                let selected = self.selected == Some(i);
                let fill = if selected { ui.visuals().selection.bg_fill.gamma_multiply(0.35) } else { Color32::TRANSPARENT };
                egui::Frame::group(ui.style()).fill(fill).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.add_enabled(doc.info.is_ok(), egui::Checkbox::without_text(&mut doc.checked));
                        let (icon, color) = match &doc.status {
                            Status::Ready if doc.info.is_err() => ("⚠", Color32::from_rgb(220, 160, 0)),
                            Status::Ready => ("📄", ui.visuals().text_color()),
                            Status::Queued => ("⏳", ui.visuals().text_color()),
                            Status::Signed(_) => ("✔", Color32::from_rgb(40, 170, 80)),
                            Status::Failed(_) => ("✖", Color32::from_rgb(210, 60, 60)),
                        };
                        ui.label(RichText::new(icon).color(color));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add_enabled(!busy, egui::Button::new("✖").small()).on_hover_text(t().remove_tip).clicked() {
                                remove = Some(i);
                            }
                            if doc.pdf {
                            ui.menu_button("🎨", |ui| {
                                ui.label(RichText::new(t().style.doc_style).strong());
                                if ui.radio(doc.style.is_none(), t().style.use_selected).clicked() {
                                    doc.style = None;
                                    doc.size = None;
                                    ui.close();
                                }
                                for s in self.styles.all() {
                                    if ui.radio(doc.style.as_deref() == Some(s.id.as_str()), &s.name).clicked() {
                                        doc.style = Some(s.id.clone());
                                        doc.size = None;
                                        ui.close();
                                    }
                                }
                            })
                            .response
                            .on_hover_text(t().style.doc_style);
                            }
                            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                let name = ui.add(egui::Label::new(RichText::new(doc.name()).strong()).truncate().sense(Sense::click()));
                                if name.clicked() {
                                    select = Some(i);
                                }
                                name.on_hover_text(doc.path.display().to_string());
                            });
                        });
                    });
                    let detail = match (&doc.info, &doc.status) {
                        (Err(e), _) => RichText::new(e).color(Color32::from_rgb(210, 60, 60)).small(),
                        (_, Status::Failed(e)) => RichText::new(e).color(Color32::from_rgb(210, 60, 60)).small(),
                        (Ok(_), _) if !doc.pdf => {
                            let ext = self.cades_format.extension();
                            RichText::new(t().other_file.replace("{size}", &human_size(doc.bytes)).replace("{ext}", ext)).weak().small()
                        }
                        (Ok(info), _) => {
                            let mut s = t().pages.replace("{n}", &info.pages.len().to_string());
                            if info.signatures > 0 {
                                s += &format!(" · {}", t().already_signed.replace("{n}", &info.signatures.to_string()));
                            }
                            if doc.placement.is_some() {
                                s += &format!(" · {}", t().placed);
                            }
                            if let Some(st) = doc.style.as_deref().and_then(|id| self.styles.get(id)) {
                                s += &format!(" · 🎨 {}", st.name);
                            }
                            RichText::new(s).weak().small()
                        }
                    };
                    if ui.add(egui::Label::new(detail).sense(Sense::click())).clicked() {
                        select = Some(i);
                    }
                    if let Status::Signed(p) = &doc.status {
                        ui.horizontal(|ui| {
                            ui.add(egui::Label::new(RichText::new(format!("→ {}", p.file_name().unwrap_or_default().to_string_lossy())).small().color(Color32::from_rgb(40, 170, 80))).truncate());
                        });
                        ui.horizontal(|ui| {
                            if ui.small_button(t().open).clicked() {
                                open(p);
                            }
                            if ui.small_button(t().reveal).clicked() {
                                reveal(p);
                            }
                        });
                    }
                });
            }
        });
        if let Some(i) = select {
            self.select(i);
        }
        if let Some(i) = remove {
            self.docs.remove(i);
            self.page_tex = None;
            self.selected = match self.selected {
                Some(s) if s == i => (!self.docs.is_empty()).then(|| i.min(self.docs.len() - 1)),
                Some(s) if s > i => Some(s - 1),
                s => s,
            };
            if let Some(s) = self.selected {
                self.select(s);
            }
        }
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // No auto-shrink: content always takes exactly the panel width, so wide content (e.g. the
        // style gallery) wraps instead of keeping a stale, wider layout from an earlier frame.
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.heading(t().cert_heading);
            let visible = self.visible_certs();
            let label = self.current_cert().map(|c| c.subject.clone()).unwrap_or_else(|| t().choose.into());
            // Right-to-left so the combo gets exactly the width left after the button; a combo that is
            // even 1px too wide makes the resizable panel grow every frame.
            let row = vec2(ui.available_width(), ui.spacing().interact_size.y);
            ui.allocate_ui_with_layout(row, egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⟳").on_hover_text(t().refresh_tip).clicked() {
                    self.reload_certs();
                }
                egui::ComboBox::from_id_salt("cert").selected_text(label).width(ui.available_width()).show_ui(ui, |ui| {
                    for i in visible {
                        let c = &self.certs[i];
                        let mut text = format!("{}  ·  {}  ·  {} {}", c.subject, c.issuer, t().until, c.not_after.format("%d.%m.%Y"));
                        if c.doc_signing {
                            text += "  ★";
                        }
                        ui.selectable_value(&mut self.cert, Some(i), text);
                    }
                });
            });
            if ui.checkbox(&mut self.show_all_certs, t().show_expired).changed() {
                self.reload_certs();
            }
            if let Some(c) = self.current_cert() {
                egui::Grid::new("certinfo").num_columns(2).spacing([8.0, 2.0]).show(ui, |ui| {
                    ui.label(RichText::new(t().issuer).weak());
                    ui.label(&c.issuer);
                    ui.end_row();
                    ui.label(RichText::new(t().valid).weak());
                    let valid = format!("{} - {}", c.not_before.format("%d.%m.%Y"), c.not_after.format("%d.%m.%Y"));
                    ui.label(if c.is_valid_now() { RichText::new(valid) } else { RichText::new(format!("{valid} {}", t().expired)).color(Color32::from_rgb(210, 60, 60)) });
                    ui.end_row();
                    ui.label(RichText::new(t().purpose).weak());
                    ui.label(if c.doc_signing { t().purpose_doc } else { t().purpose_general });
                    ui.end_row();
                    ui.label(RichText::new(t().thumbprint).weak());
                    ui.label(RichText::new(c.thumbprint_hex()).monospace().small());
                    ui.end_row();
                });
            }

            ui.separator();
            ui.heading(t().meta_heading);
            // Fields get exactly the room left by the widest label, otherwise the panel grows every frame.
            let label_w = [t().reason, t().location, t().contact].iter().map(|s| text_width(ui, s)).fold(0.0, f32::max);
            let field_w = ui.available_width() - label_w - 8.0 - 2.0;
            egui::Grid::new("meta").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label(t().reason);
                ui.add(egui::TextEdit::singleline(&mut self.reason).hint_text(t().reason_hint).desired_width(field_w));
                ui.end_row();
                ui.label(t().location);
                ui.add(egui::TextEdit::singleline(&mut self.location).hint_text(t().location_hint).desired_width(field_w));
                ui.end_row();
                ui.label(t().contact);
                ui.add(egui::TextEdit::singleline(&mut self.contact).hint_text(t().contact_hint).desired_width(field_w));
                ui.end_row();
            });
            if ui.checkbox(&mut self.use_tsa, t().tsa_enable).on_hover_text(t().tsa_hint).changed() {
                settings::set("tsa", if self.use_tsa { "1" } else { "0" });
            }
            ui.add_enabled_ui(self.use_tsa, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    let edit = ui.add(egui::TextEdit::singleline(&mut self.tsa_url).hint_text(tsa::DEFAULT_URL).desired_width(ui.available_width()));
                    if edit.lost_focus() {
                        if self.tsa_url.trim().is_empty() {
                            self.tsa_url = tsa::DEFAULT_URL.into();
                        }
                        settings::set("tsa_url", self.tsa_url.trim());
                    }
                });
            });

            ui.separator();
            ui.heading(t().style.heading);
            ui.checkbox(&mut self.visible, t().stamp_enable);
            let data = self.stamp_data();
            ui.add_enabled_ui(self.visible, |ui| {
                self.styles.panel(ui, &data);
                ui.label(RichText::new(t().stamp_hint).weak().small());
                ui.horizontal_wrapped(|ui| {
                    if ui.button(t().reset_pos).clicked() {
                        for d in &mut self.docs {
                            d.placement = None;
                            d.size = None;
                        }
                    }
                    let current = self.selected.and_then(|i| self.docs[i].placement.map(|p| (p, self.docs[i].size)));
                    if ui
                        .add_enabled(current.is_some(), egui::Button::new(t().apply_all))
                        .on_hover_text(t().apply_all_tip)
                        .clicked()
                    {
                        let (p, size) = current.unwrap();
                        for d in &mut self.docs {
                            if let Ok(info) = &d.info {
                                d.placement = Some(Placement { page: p.page.min(info.pages.len() - 1), ..p });
                                d.size = size;
                            }
                        }
                    }
                });
            });

            ui.separator();
            ui.heading(t().output_heading);
            ui.radio_value(&mut self.output, Output::Suffix, t().output_new);
            ui.add_enabled_ui(self.output == Output::Suffix, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    ui.label(t().suffix_label);
                    ui.add(egui::TextEdit::singleline(&mut self.suffix).desired_width(140.0));
                });
            });
            ui.radio_value(&mut self.output, Output::Overwrite, t().output_overwrite);
            if self.docs.iter().any(|d| !d.pdf) {
                ui.add_space(4.0);
                ui.label(RichText::new(t().other_files).strong());
                let before = self.cades_format;
                ui.radio_value(&mut self.cades_format, cades::Format::Detached, t().p7s_label);
                ui.radio_value(&mut self.cades_format, cades::Format::Enveloping, t().p7m_label);
                ui.radio_value(&mut self.cades_format, cades::Format::Asice, t().asice_label).on_hover_text(t().asice_hint);
                if self.cades_format != before {
                    settings::set("cades", self.cades_format.code());
                }
            }
            ui.checkbox(&mut self.open_folder_after, t().open_folder);

            ui.add_space(12.0);
            let count = self.docs.iter().filter(|d| d.checked && d.info.is_ok()).count();
            let busy = self.job.is_some();
            let ready = count > 0 && self.current_cert().is_some() && !busy && (self.output == Output::Overwrite || !self.suffix.trim().is_empty());
            let text = if busy { t().signing_btn.to_string() } else { t().sign_btn.replace("{n}", &count.to_string()) };
            let btn = egui::Button::new(RichText::new(text).size(18.0).strong()).min_size(vec2(ui.available_width(), 44.0));
            if ui.add_enabled(ready, btn).clicked() {
                self.start_signing(ctx);
            }
            if !ready && !busy {
                let why = if self.current_cert().is_none() {
                    t().why_cert
                } else if count == 0 {
                    t().why_docs
                } else {
                    t().why_suffix
                };
                ui.label(RichText::new(why).weak().small());
            }
            if busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(t().pin_hint);
                });
            }
        });
    }

    fn stamp_texture(&mut self, ctx: &egui::Context, doc: usize) -> TextureHandle {
        let data = self.stamp_data();
        let s = self.doc_style(&self.docs[doc]).clone();
        let size = self.doc_size(&self.docs[doc]);
        self.styles.texture(ctx, "page", &s, &data, size.x, size.y, 3.0).0
    }

    fn preview_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(sel) = self.selected else {
            ui.centered_and_justified(|ui| ui.label(RichText::new(t().preview_empty).weak().size(16.0)));
            return;
        };
        let info = match &self.docs[sel].info {
            Ok(i) => i.clone(),
            Err(e) => {
                let msg = format!("{}\n{e}", t().cannot_open);
                ui.centered_and_justified(|ui| ui.label(RichText::new(msg).color(Color32::from_rgb(210, 60, 60))));
                return;
            }
        };
        if !self.docs[sel].pdf {
            let msg = t().no_preview_other.replace("{ext}", self.cades_format.extension());
            ui.centered_and_justified(|ui| ui.label(RichText::new(format!("📦\n\n{}\n\n{msg}", self.docs[sel].name())).weak().size(15.0)));
            return;
        }
        let n = info.pages.len();
        self.page = self.page.min(n - 1);

        ui.horizontal(|ui| {
            if ui.add_enabled(self.page > 0, egui::Button::new("◀")).clicked() {
                self.page -= 1;
            }
            ui.label(t().page_of.replace("{p}", &(self.page + 1).to_string()).replace("{n}", &n.to_string()));
            if ui.add_enabled(self.page + 1 < n, egui::Button::new("▶")).clicked() {
                self.page += 1;
            }
            ui.separator();
            ui.add(egui::Label::new(RichText::new(self.docs[sel].path.display().to_string()).weak().small()).truncate());
        });
        if ui.input(|i| i.key_pressed(egui::Key::PageDown)) && self.page + 1 < n {
            self.page += 1;
        }
        if ui.input(|i| i.key_pressed(egui::Key::PageUp)) && self.page > 0 {
            self.page -= 1;
        }

        let path = self.docs[sel].path.clone();
        let stale = !matches!(&self.page_tex, Some((p, pg, _)) if *p == path && *pg == self.page);
        if stale && self.previewer.available() {
            let tex = self
                .previewer
                .render(&path, self.page, 1400)
                .map(|img| ctx.load_texture("page", img, TextureOptions::LINEAR))
                .map_err(|e| format!("{e:#}"));
            self.page_tex = Some((path.clone(), self.page, tex));
        }

        let (pw, ph) = info.pages[self.page].display_size();
        let avail = ui.available_size() - vec2(0.0, 4.0);
        let scale = (avail.x / pw).min(avail.y / ph).max(0.05);
        let size = vec2(pw * scale, ph * scale);
        let (outer, _) = ui.allocate_exact_size(avail, Sense::hover());
        let rect = egui::Rect::from_center_size(outer.center(), size);
        let resp = ui.interact(rect, ui.scope_id().with("page"), Sense::click_and_drag());
        let painter = ui.painter_at(outer);

        painter.rect_filled(rect.translate(vec2(3.0, 3.0)), 2.0, Color32::from_black_alpha(60));
        painter.rect_filled(rect, 0.0, Color32::WHITE);
        let uv = egui::Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
        match &self.page_tex {
            Some((p, pg, Ok(tex))) if *p == path && *pg == self.page => {
                painter.image(tex.id(), rect, uv, Color32::WHITE);
            }
            Some((p, pg, Err(e))) if *p == path && *pg == self.page => {
                painter.text(rect.center(), egui::Align2::CENTER_CENTER, format!("{}\n{e}", t().preview_unavailable), egui::FontId::proportional(14.0), Color32::GRAY);
            }
            _ if !self.previewer.available() => {
                painter.text(rect.center(), egui::Align2::CENTER_CENTER, t().no_pdfium, egui::FontId::proportional(14.0), Color32::GRAY);
            }
            _ => {}
        }

        if !self.visible {
            return;
        }
        if resp.hovered() {
            ctx.set_cursor_icon(egui::CursorIcon::Crosshair);
        }
        let size = self.doc_size(&self.docs[sel]);
        if (resp.clicked() || resp.dragged())
            && let Some(pos) = resp.interact_pointer_pos()
        {
            let local = (pos - rect.min) / scale;
            self.docs[sel].placement = Some(Placement {
                page: self.page,
                x: (local.x - size.x / 2.0).clamp(0.0, (pw - size.x).max(0.0)),
                y: (local.y - size.y / 2.0).clamp(0.0, (ph - size.y).max(0.0)),
            });
        }
        if let Some(p) = self.placement_for(&self.docs[sel]) {
            if p.page == self.page {
                let srect = egui::Rect::from_min_size(rect.min + vec2(p.x, p.y) * scale, size * scale);
                let explicit = self.docs[sel].placement.is_some();
                let tex = self.stamp_texture(ctx, sel);
                painter.image(tex.id(), srect, uv, Color32::WHITE);
                // Placement frame (not part of the stamp).
                let accent = ui.visuals().selection.bg_fill;
                let stroke = Stroke::new(if explicit { 1.5 } else { 1.0 }, accent.gamma_multiply(0.8));
                painter.rect_stroke(srect.expand(2.0), 2.0, stroke, StrokeKind::Outside);
                if !explicit {
                    painter.text(srect.left_top() - vec2(0.0, 4.0), egui::Align2::LEFT_BOTTOM, t().default_pos, egui::FontId::proportional(11.0), Color32::GRAY);
                }
                self.resize_handles(ui, ctx, sel, rect, srect, scale, (pw, ph), size);
            } else {
                painter.text(rect.center_top() + vec2(0.0, 12.0), egui::Align2::CENTER_TOP, t().stamp_on_page.replace("{n}", &(p.page + 1).to_string()), egui::FontId::proportional(13.0), Color32::GRAY);
            }
        }
    }

    /// Corner handles on the stamp: drag to resize around the opposite corner. Shift keeps the
    /// proportions; a round seal always does.
    #[allow(clippy::too_many_arguments)]
    fn resize_handles(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, sel: usize, page: egui::Rect, srect: egui::Rect, scale: f32, (pw, ph): (f32, f32), size: Vec2) {
        const MIN: Vec2 = vec2(30.0, 20.0);
        let keep_aspect = self.doc_style(&self.docs[sel]).shape == style::Shape::Seal || ui.input(|i| i.modifiers.shift);
        let corners = [srect.left_top(), srect.right_top(), srect.left_bottom(), srect.right_bottom()];
        let accent = ui.visuals().selection.bg_fill;
        for (ci, c) in corners.iter().enumerate() {
            let hr = egui::Rect::from_center_size(*c, vec2(10.0, 10.0));
            let h = ui.interact(hr, ui.scope_id().with(("stamp-resize", ci)), Sense::drag());
            ui.painter().rect_filled(hr.shrink(1.0), 2.0, accent);
            ui.painter().rect_stroke(hr.shrink(1.0), 2.0, Stroke::new(1.0, Color32::WHITE), StrokeKind::Inside);
            if h.hovered() || h.dragged() {
                ctx.set_cursor_icon(if ci == 0 || ci == 3 { egui::CursorIcon::ResizeNwSe } else { egui::CursorIcon::ResizeNeSw });
            }
            if h.drag_started() {
                self.resizing = Some((ci, ((corners[3 - ci] - page.min) / scale).to_pos2()));
            }
            if h.dragged()
                && let (Some((_, anchor)), Some(pos)) = (self.resizing, h.interact_pointer_pos())
            {
                let cur = ((pos - page.min) / scale).to_pos2();
                let mut w = (cur.x - anchor.x).abs().clamp(MIN.x, pw);
                let mut hh = (cur.y - anchor.y).abs().clamp(MIN.y, ph);
                if keep_aspect {
                    let a = size.x / size.y;
                    if w / hh > a { hh = (w / a).min(ph) } else { w = (hh * a).min(pw) }
                }
                let x = if cur.x < anchor.x { anchor.x - w } else { anchor.x };
                let y = if cur.y < anchor.y { anchor.y - hh } else { anchor.y };
                let doc = &mut self.docs[sel];
                doc.placement = Some(Placement { page: self.page, x: x.clamp(0.0, (pw - w).max(0.0)), y: y.clamp(0.0, (ph - hh).max(0.0)) });
                doc.size = Some(vec2(w, hh));
            }
            if h.drag_stopped() {
                self.resizing = None;
            }
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("✍ Doc Signer").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut lang = i18n::current();
                egui::ComboBox::from_id_salt("lang")
                    .selected_text(format!("🌐 {}", lang.native_name()))
                    .show_ui(ui, |ui| {
                        for l in i18n::Lang::ALL {
                            ui.selectable_value(&mut lang, l, l.native_name());
                        }
                    })
                    .response
                    .on_hover_text(t().language);
                if lang != i18n::current() {
                    self.set_language(ctx, lang);
                }
            });
        });
    }

    fn set_language(&mut self, ctx: &egui::Context, lang: i18n::Lang) {
        if self.suffix == t().default_suffix {
            self.suffix = i18n::tr(lang).default_suffix.into();
        }
        i18n::set(lang);
        i18n::save(lang);
        self.styles.reload();
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(t().window_title.into()));
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong(t().log_heading);
            if ui.small_button(t().clear).clicked() {
                self.log.clear();
            }
        });
        egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
            for (level, msg) in &self.log {
                let color = match level {
                    Level::Info => ui.visuals().text_color(),
                    Level::Ok => Color32::from_rgb(40, 170, 80),
                    Level::Err => Color32::from_rgb(210, 60, 60),
                };
                ui.label(RichText::new(msg).color(color).monospace().small());
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        self.poll_job();

        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        for p in dropped {
            if p.is_dir() {
                if let Ok(rd) = std::fs::read_dir(&p) {
                    for e in rd.flatten() {
                        if e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("pdf")) {
                            self.add_file(e.path());
                        }
                    }
                }
            } else {
                self.add_file(p);
            }
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::O)) {
            self.pick_files();
        }

        egui::Panel::top("top").show(ui, |ui| self.top_bar(ui, ctx));
        egui::Panel::bottom("log").resizable(true).default_size(110.0).size_range(60.0..=320.0).show(ui, |ui| self.log_panel(ui));
        egui::Panel::left("docs").resizable(true).default_size(320.0).size_range(240.0..=480.0).show(ui, |ui| self.documents_panel(ui));
        egui::Panel::right("settings").resizable(true).default_size(360.0).size_range(320.0..=520.0).show(ui, |ui| self.settings_panel(ui, ctx));
        egui::CentralPanel::default().show(ui, |ui| self.preview_panel(ui, ctx));

        let data = self.stamp_data();
        self.styles.windows(ctx, &data, &self.previewer);
        for note in self.styles.take_notes() {
            match note {
                style_ui::Note::Ok(m) => self.push(Level::Ok, m),
                style_ui::Note::Err(m) => self.push(Level::Err, m),
            }
        }

        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::unique("drop")));
            let screen = ctx.content_rect();
            painter.rect_filled(screen, 0.0, Color32::from_black_alpha(150));
            painter.text(screen.center(), egui::Align2::CENTER_CENTER, t().drop_overlay, egui::FontId::proportional(28.0), Color32::WHITE);
        }
    }
}

/// System UI fonts (same lookup as the stamp, see `fonts`); egui's built-in fonts stay as fallback.
fn install_fonts(ctx: &egui::Context) {
    let mut defs = egui::FontDefinitions::default();
    let mut add = |name: String, bytes: Vec<u8>, family: egui::FontFamily, first: bool| {
        defs.font_data.insert(name.clone(), Arc::new(egui::FontData::from_owned(bytes)));
        let list = defs.families.entry(family).or_default();
        if first { list.insert(0, name) } else { list.push(name) }
    };
    if let Some(b) = fonts::find(fonts::SYSTEM.regular) {
        add("system-sans".into(), b, egui::FontFamily::Proportional, true);
    }
    for (i, file) in fonts::SYSTEM.symbols.iter().enumerate() {
        if let Some(b) = fonts::find(&[file]) {
            add(format!("system-symbols-{i}"), b, egui::FontFamily::Proportional, false);
        }
    }
    if let Some(b) = fonts::find(fonts::SYSTEM.mono) {
        add("system-mono".into(), b, egui::FontFamily::Monospace, true);
    }
    ctx.set_fonts(defs);
}

fn open(p: &Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(not(windows))]
    let _ = std::process::Command::new("xdg-open").arg(p).spawn();
}

fn reveal(p: &Path) {
    #[cfg(windows)]
    {
        let mut arg = std::ffi::OsString::from("/select,");
        arg.push(p);
        let _ = std::process::Command::new("explorer").arg(arg).spawn();
    }
    #[cfg(not(windows))]
    {
        let dir = p.parent().unwrap_or_else(|| Path::new("."));
        let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
    }
}

fn human_size(b: u64) -> String {
    match b {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.0} KB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

fn text_width(ui: &egui::Ui, s: &str) -> f32 {
    egui::WidgetText::from(s).into_galley(ui, Some(egui::TextWrapMode::Extend), f32::INFINITY, egui::TextStyle::Body).size().x
}

