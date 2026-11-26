//! Stamp-style UI: gallery, actions menu, style editor and the import / rename / delete dialogs.

use std::collections::HashMap;
use std::path::Path;

use eframe::egui::{self, Color32, Pos2, RichText, Sense, TextureHandle, TextureOptions, vec2};

use crate::i18n::{self, t};
use crate::image_src::{self, Raster};
use crate::preview::Previewer;
use crate::settings;
use crate::stamp;
use crate::style::{self, Align, BorderStyle, Field, FieldKind, FontFamily, ImagePosition, Rgb, Shape, StampData, Style, StyleImage};

/// Drawing canvas size (logical points).
const CANVAS: egui::Vec2 = egui::Vec2::new(560.0, 200.0);

struct DrawPad {
    strokes: Vec<Vec<Pos2>>,
    width: f32,
    color: [u8; 3],
}

impl DrawPad {
    fn new() -> Self {
        DrawPad { strokes: Vec::new(), width: 2.5, color: [0x10, 0x20, 0x60] }
    }

    /// Smooth (Catmull-Rom) strokes with round caps, rendered at `image_src::MAX_SIDE` width and trimmed.
    fn rasterize(&self) -> Option<Raster> {
        use tiny_skia::{LineCap, LineJoin, Paint, PathBuilder, Pixmap, Stroke, Transform};
        let s = image_src::MAX_SIDE as f32 / CANVAS.x;
        let mut pm = Pixmap::new((CANVAS.x * s) as u32, (CANVAS.y * s) as u32)?;
        let mut paint = Paint::default();
        paint.set_color_rgba8(self.color[0], self.color[1], self.color[2], 255);
        paint.anti_alias = true;
        let stroke = Stroke { width: self.width * s, line_cap: LineCap::Round, line_join: LineJoin::Round, ..Stroke::default() };
        for st in self.strokes.iter().filter(|st| !st.is_empty()) {
            let p: Vec<(f32, f32)> = st.iter().map(|q| (q.x * s, q.y * s)).collect();
            let mut pb = PathBuilder::new();
            pb.move_to(p[0].0, p[0].1);
            if p.len() == 1 {
                pb.line_to(p[0].0 + 0.01, p[0].1);
            }
            let n = p.len();
            for i in 0..n.saturating_sub(1) {
                let (a, b, c, d) = (p[i.saturating_sub(1)], p[i], p[i + 1], p[(i + 2).min(n - 1)]);
                let c1 = (b.0 + (c.0 - a.0) / 6.0, b.1 + (c.1 - a.1) / 6.0);
                let c2 = (c.0 - (d.0 - b.0) / 6.0, c.1 - (d.1 - b.1) / 6.0);
                pb.cubic_to(c1.0, c1.1, c2.0, c2.1, c.0, c.1);
            }
            if let Some(path) = pb.finish() {
                pm.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
            }
        }
        let rgba = pm
            .pixels()
            .iter()
            .flat_map(|p| {
                let c = p.demultiply();
                [c.red(), c.green(), c.blue(), c.alpha()]
            })
            .collect();
        let r = image_src::trim(&Raster { width: pm.width(), height: pm.height(), rgba });
        (r.width > 1).then_some(r)
    }
}

pub enum Note {
    Ok(String),
    Err(String),
}

struct Editor {
    style: Style,
    /// Id of the edited style; `None` when the original is read-only (saving creates a copy).
    target: Option<String>,
}

struct Rename {
    id: String,
    name: String,
}

/// Quick palettes: (text, border, background).
const PALETTES: [(Rgb, Rgb, Rgb); 5] = [
    (Rgb::INK, Rgb::TEAL, Rgb::TEAL),
    (Rgb::INK, Rgb::INK, Rgb::INK),
    (Rgb([0x1b, 0x6e, 0x3a]), Rgb([0x1b, 0x6e, 0x3a]), Rgb([0x1b, 0x6e, 0x3a])),
    (Rgb([0x9b, 0x1c, 0x1c]), Rgb([0x9b, 0x1c, 0x1c]), Rgb([0x9b, 0x1c, 0x1c])),
    (Rgb([0x22, 0x22, 0x22]), Rgb([0x22, 0x22, 0x22]), Rgb([0x22, 0x22, 0x22])),
];

pub struct StyleUi {
    styles: Vec<Style>,
    current: String,
    editor: Option<Editor>,
    import_queue: Vec<Style>,
    confirm_delete: Option<String>,
    rename: Option<Rename>,
    pad: Option<DrawPad>,
    /// Signature appearances found in a PDF, with thumbnails, waiting for a choice.
    sig_pick: Option<Vec<(crate::pdf::Appearance, TextureHandle)>>,
    textures: HashMap<String, (String, TextureHandle)>,
    notes: Vec<Note>,
}

fn fingerprint(s: &Style, data: &StampData, w: f32, h: f32, scale: f32) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{w}|{h}|{scale}|{}",
        i18n::current().code(),
        s.fingerprint(),
        data.name,
        data.issuer,
        data.reason,
        data.location,
        data.contact,
        data.time.format("%Y%m%d%H%M"),
    )
}

fn field_name(kind: FieldKind) -> &'static str {
    let s = &t().style;
    match kind {
        FieldKind::Label => s.field_label,
        FieldKind::Name => s.field_name,
        FieldKind::Date => s.field_date,
        FieldKind::Reason => s.field_reason,
        FieldKind::Location => s.field_location,
        FieldKind::Issuer => s.field_issuer,
        FieldKind::Contact => s.field_contact,
        FieldKind::Custom => s.field_custom,
    }
}

impl StyleUi {
    pub fn new() -> Self {
        let mut ui = StyleUi {
            styles: Vec::new(),
            current: settings::get("style").unwrap_or_else(|| style::CLASSIC_ID.into()),
            editor: None,
            import_queue: Vec::new(),
            confirm_delete: None,
            rename: None,
            pad: None,
            sig_pick: None,
            textures: HashMap::new(),
            notes: Vec::new(),
        };
        ui.reload();
        ui
    }

    /// Built-ins (in the current language) followed by the user's styles.
    pub fn reload(&mut self) {
        let (user, errors) = style::load_user();
        self.styles = style::builtins();
        self.styles.extend(user);
        for e in errors {
            self.notes.push(Note::Err(format!("{}: {e}", t().style.err_load)));
        }
        if !self.styles.iter().any(|s| s.id == self.current) {
            self.current = style::CLASSIC_ID.into();
        }
        self.textures.clear();
    }

    pub fn take_notes(&mut self) -> Vec<Note> {
        std::mem::take(&mut self.notes)
    }

    pub fn current(&self) -> &Style {
        self.styles.iter().find(|s| s.id == self.current).unwrap_or(&self.styles[0])
    }

    /// Selects a style and remembers it as the default.
    pub fn select(&mut self, id: &str) -> Option<&Style> {
        if !self.styles.iter().any(|s| s.id == id) {
            return None;
        }
        self.current = id.to_string();
        settings::set("style", id);
        Some(self.current())
    }

    /// Texture of `s` rendered with `data` (cached per slot until anything changes).
    pub fn texture(&mut self, ctx: &egui::Context, slot: &str, s: &Style, data: &StampData, w: f32, h: f32, scale: f32) -> (TextureHandle, bool) {
        let key = fingerprint(s, data, w, h, scale);
        if let Some((k, tex)) = self.textures.get(slot) {
            if *k == key {
                return (tex.clone(), false);
            }
        }
        let r = stamp::render(s, data, w, h, scale);
        let img = egui::ColorImage::from_rgba_unmultiplied([r.width as usize, r.height as usize], &r.rgba);
        let tex = ctx.load_texture(format!("stamp-{slot}"), img, TextureOptions::LINEAR);
        self.textures.insert(slot.to_string(), (key, tex.clone()));
        (tex, r.clipped)
    }

    fn unique_name(&self, base: &str) -> String {
        if !self.styles.iter().any(|s| s.name == base) {
            return base.to_string();
        }
        (2..).map(|n| format!("{base} ({n})")).find(|n| !self.styles.iter().any(|s| &s.name == n)).unwrap()
    }

    fn store(&mut self, s: Style) -> bool {
        match style::save(&s) {
            Ok(()) => {
                let id = s.id.clone();
                self.reload();
                self.select(&id);
                true
            }
            Err(e) => {
                self.notes.push(Note::Err(format!("{e:#}")));
                false
            }
        }
    }

    fn duplicate(&mut self, id: &str) {
        if let Some(src) = self.styles.iter().find(|s| s.id == id).cloned() {
            let mut copy = src;
            copy.id = style::new_id();
            copy.builtin = false;
            copy.locked = false;
            copy.name = self.unique_name(&format!("{} {}", copy.name, t().style.copy_suffix));
            if self.store(copy.clone()) {
                self.notes.push(Note::Ok(format!("{}: {}", t().style.saved, copy.name)));
            }
        }
    }

    fn open_editor(&mut self, id: &str) {
        if let Some(s) = self.styles.iter().find(|s| s.id == id).cloned() {
            let target = (!s.read_only()).then(|| s.id.clone());
            self.editor = Some(Editor { style: s, target });
        }
    }

    fn export(&mut self, id: &str) {
        let Some(s) = self.styles.iter().find(|s| s.id == id).cloned() else { return };
        let file: String = s.name.chars().map(|c| if c.is_alphanumeric() || c == ' ' || c == '-' { c } else { '_' }).collect();
        if let Some(path) = rfd::FileDialog::new()
            .set_title(t().style.export_title)
            .add_filter(t().style.filter, &["json"])
            .set_file_name(format!("{}.json", file.trim()))
            .save_file()
        {
            match style::export(&s, &path) {
                Ok(()) => self.notes.push(Note::Ok(format!("{}: {}", t().style.exported, path.display()))),
                Err(e) => self.notes.push(Note::Err(format!("{e:#}"))),
            }
        }
    }

    fn import(&mut self) {
        let Some(paths) = rfd::FileDialog::new().set_title(t().style.import_title).add_filter(t().style.filter, &["json"]).pick_files() else {
            return;
        };
        for p in paths {
            match style::import(&p) {
                Ok(s) => self.import_queue.push(s),
                Err(e) => self.notes.push(Note::Err(format!("{}: {e:#}", t().style.err_load))),
            }
        }
    }

    /// Stores queued imports that do not clash; returns true while a clash waits for a decision.
    fn process_imports(&mut self) -> bool {
        while let Some(s) = self.import_queue.first().cloned() {
            if self.styles.iter().any(|x| x.name == s.name) {
                return true;
            }
            self.import_queue.remove(0);
            let name = s.name.clone();
            if self.store(s) {
                self.notes.push(Note::Ok(format!("{}: {name}", t().style.imported)));
            }
        }
        false
    }

    /// The "Stamp appearance" section of the right panel.
    pub fn panel(&mut self, ui: &mut egui::Ui, data: &StampData) {
        let ts = &t().style;
        let ctx = ui.ctx().clone();
        let mut select = None;
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
            let styles = self.styles.clone();
            for s in &styles {
                let thumb_w = 96.0;
                let scale = thumb_w / s.size.w * 2.0;
                let (tex, _) = self.texture(&ctx, &format!("thumb-{}", s.id), s, data, s.size.w, s.size.h, scale);
                let size = vec2(thumb_w, thumb_w * s.size.h / s.size.w).min(vec2(thumb_w, 56.0));
                let selected = s.id == self.current;
                ui.vertical(|ui| {
                    ui.set_width(thumb_w + 8.0);
                    let image = egui::Image::from_texture(&tex).fit_to_exact_size(size).bg_fill(Color32::WHITE);
                    let mut hover = s.name.clone();
                    if s.builtin {
                        hover += &format!(" · {}", ts.builtin_tag);
                    } else if s.locked {
                        hover += &format!(" · {}", ts.locked_tag);
                    }
                    if ui.add(egui::Button::image(image).selected(selected)).on_hover_text(hover).clicked() {
                        select = Some(s.id.clone());
                    }
                    let mut name = RichText::new(&s.name).small();
                    if selected {
                        name = name.strong();
                    }
                    ui.add(egui::Label::new(name).truncate());
                });
            }
        });
        if let Some(id) = select {
            self.select(&id);
        }

        let cur = self.current().clone();
        ui.horizontal(|ui| {
            ui.label(ts.style);
            ui.strong(&cur.name);
            if cur.builtin {
                ui.label(RichText::new(ts.builtin_tag).weak().small());
            } else if cur.locked {
                ui.label(RichText::new(format!("🔒 {}", ts.locked_tag)).weak().small());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.menu_button("⋯", |ui| {
                    if ui.button(ts.duplicate).clicked() {
                        self.duplicate(&cur.id);
                        ui.close();
                    }
                    if ui.add_enabled(!cur.read_only(), egui::Button::new(ts.rename)).clicked() {
                        self.rename = Some(Rename { id: cur.id.clone(), name: cur.name.clone() });
                        ui.close();
                    }
                    ui.separator();
                    if ui.button(ts.export).clicked() {
                        ui.close();
                        self.export(&cur.id);
                    }
                    if ui.button(ts.import).clicked() {
                        ui.close();
                        self.import();
                    }
                    ui.separator();
                    if ui.add_enabled(!cur.builtin, egui::Button::new(ts.delete)).clicked() {
                        self.confirm_delete = Some(cur.id.clone());
                        ui.close();
                    }
                })
                .response
                .on_hover_text(ts.more);
                if ui.button(ts.edit).clicked() {
                    self.open_editor(&cur.id);
                }
            });
        });
    }

    /// Dialogs and the editor window; call once per frame.
    pub fn windows(&mut self, ctx: &egui::Context, data: &StampData, previewer: &Previewer) {
        self.editor_window(ctx, data, previewer);
        self.pad_window(ctx);
        self.sig_pick_window(ctx, previewer);
        self.dialogs(ctx);
    }

    /// Sets the editor's picture from a raster (keeps position/opacity of an existing one).
    fn set_picture(&mut self, r: Raster) {
        let Some(ed) = &mut self.editor else { return };
        let opaque = r.is_opaque();
        let r = if opaque { r } else { image_src::trim(&r) };
        match image_src::to_png_base64(&r) {
            Ok(b64) => {
                let old = ed.style.image.take();
                ed.style.image = Some(StyleImage {
                    png_base64: b64,
                    position: old.as_ref().map_or(ImagePosition::Left, |o| o.position),
                    opacity: old.as_ref().map_or(1.0, |o| o.opacity),
                    // Scans and photos have a white background; drawings and PNG/SVG logos are transparent.
                    remove_background: opaque.then_some(0.9),
                });
            }
            Err(e) => self.notes.push(Note::Err(format!("{}: {e:#}", t().style.err_image))),
        }
    }

    fn pick_picture(&mut self, previewer: &Previewer) {
        let ts = &t().style;
        let Some(path) = rfd::FileDialog::new().add_filter(ts.image_filter, &["png", "jpg", "jpeg", "svg", "pdf"]).pick_file() else {
            return;
        };
        let pdf = |p: &Path| previewer.render_raster(p, image_src::MAX_SIDE);
        match image_src::load_file(&path, &pdf) {
            Ok(r) => self.set_picture(r),
            Err(e) => self.notes.push(Note::Err(format!("{}: {}: {e:#}", ts.err_image, path.display()))),
        }
    }

    /// Reads the signature appearances of a chosen PDF and opens the chooser.
    fn open_sig_pick(&mut self, ctx: &egui::Context, previewer: &Previewer) {
        let ts = &t().style;
        let Some(path) = rfd::FileDialog::new().add_filter("PDF", &["pdf"]).pick_file() else { return };
        let found = std::fs::read(&path).map_err(anyhow::Error::from).and_then(|b| crate::pdf::signature_appearances(&b));
        match found {
            Ok(list) if list.is_empty() => self.notes.push(Note::Err(format!("{}: {}", ts.no_appearances, path.display()))),
            Ok(list) => {
                let mut items = Vec::new();
                for (i, a) in list.into_iter().enumerate() {
                    match previewer.render_bytes_raster(&a.pdf, 480) {
                        Ok(r) => {
                            let img = egui::ColorImage::from_rgba_unmultiplied([r.width as usize, r.height as usize], &r.rgba);
                            items.push((a, ctx.load_texture(format!("sig-pick-{i}"), img, TextureOptions::LINEAR)));
                        }
                        Err(e) => self.notes.push(Note::Err(format!("{}: {e:#}", ts.err_image))),
                    }
                }
                if !items.is_empty() {
                    self.sig_pick = Some(items);
                }
            }
            Err(e) => self.notes.push(Note::Err(format!("{}: {}: {e:#}", ts.err_image, path.display()))),
        }
    }

    fn sig_pick_window(&mut self, ctx: &egui::Context, previewer: &Previewer) {
        let Some(items) = self.sig_pick.take() else { return };
        let ts = &t().style;
        let mut chosen: Option<usize> = None;
        let mut cancel = false;
        egui::Modal::new(egui::Id::unique("style-sig-pick")).show(ctx, |ui| {
            ui.heading(ts.pick_title);
            ui.colored_label(Color32::from_rgb(220, 140, 0), format!("⚠ {}", ts.pick_warning));
            ui.add_space(6.0);
            egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                for (i, (a, tex)) in items.iter().enumerate() {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let max = vec2(300.0, 100.0);
                            let s = (max.x / a.size.0).min(max.y / a.size.1);
                            ui.add(egui::Image::from_texture(tex).fit_to_exact_size(vec2(a.size.0 * s, a.size.1 * s)).bg_fill(Color32::WHITE));
                            ui.vertical(|ui| {
                                let who = if a.signer.is_empty() { "—" } else { a.signer.as_str() };
                                ui.label(ts.signer_page.replace("{signer}", who).replace("{page}", &(a.page + 1).to_string()));
                                if ui.button(RichText::new(ts.use_drawing).strong()).clicked() {
                                    chosen = Some(i);
                                }
                            });
                        });
                    });
                }
            });
            if ui.button(ts.cancel).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                cancel = true;
            }
        });
        if let Some(i) = chosen {
            match previewer.render_bytes_raster(&items[i].0.pdf, image_src::MAX_SIDE) {
                Ok(r) => self.set_picture(r),
                Err(e) => self.notes.push(Note::Err(format!("{}: {e:#}", ts.err_image))),
            }
        } else if !cancel {
            self.sig_pick = Some(items);
        }
    }

    fn pad_window(&mut self, ctx: &egui::Context) {
        let Some(mut pad) = self.pad.take() else { return };
        let ts = &t().style;
        let mut done: Option<bool> = None;
        egui::Modal::new(egui::Id::unique("style-draw")).show(ctx, |ui| {
            ui.heading(ts.draw_title);
            let (resp, painter) = ui.allocate_painter(CANVAS, Sense::drag());
            let origin = resp.rect.min;
            painter.rect_filled(resp.rect, 4.0, Color32::WHITE);
            // Signature line.
            let base_y = resp.rect.bottom() - 40.0;
            painter.line_segment([Pos2::new(resp.rect.left() + 20.0, base_y), Pos2::new(resp.rect.right() - 20.0, base_y)], (1.0, Color32::LIGHT_GRAY));
            if resp.drag_started() {
                pad.strokes.push(Vec::new());
            }
            if (resp.dragged() || resp.drag_started())
                && let Some(pos) = resp.interact_pointer_pos()
            {
                let local = (pos - origin).to_pos2();
                if let Some(st) = pad.strokes.last_mut() {
                    if st.last().is_none_or(|l: &Pos2| l.distance(local) > 0.7) {
                        st.push(local);
                    }
                }
            }
            let [r, g, b] = pad.color;
            let stroke = egui::Stroke::new(pad.width, Color32::from_rgb(r, g, b));
            for st in &pad.strokes {
                let pts: Vec<Pos2> = st.iter().map(|p| origin + p.to_vec2()).collect();
                if pts.len() == 1 {
                    painter.circle_filled(pts[0], pad.width / 2.0, stroke.color);
                } else {
                    painter.add(egui::Shape::line(pts, stroke));
                }
            }
            ui.horizontal(|ui| {
                ui.label(ts.pen);
                ui.add(egui::Slider::new(&mut pad.width, 1.0..=8.0));
                ui.color_edit_button_srgb(&mut pad.color);
                if ui.add_enabled(!pad.strokes.is_empty(), egui::Button::new(ts.undo)).clicked() {
                    pad.strokes.pop();
                }
                if ui.add_enabled(!pad.strokes.is_empty(), egui::Button::new(t().clear)).clicked() {
                    pad.strokes.clear();
                }
            });
            ui.horizontal(|ui| {
                if ui.button(ts.cancel).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    done = Some(false);
                }
                let ok = !pad.strokes.is_empty();
                if ui.add_enabled(ok, egui::Button::new(RichText::new(ts.use_drawing).strong())).clicked()
                    || (ok && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                {
                    done = Some(true);
                }
            });
        });
        match done {
            Some(true) => {
                if let Some(r) = pad.rasterize() {
                    self.set_picture(r);
                }
            }
            Some(false) => {}
            None => self.pad = Some(pad),
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let ts = &t().style;
        if self.process_imports() {
            let s = self.import_queue[0].clone();
            let mut decision = None;
            egui::Modal::new(egui::Id::unique("style-import-conflict")).show(ctx, |ui| {
                ui.heading(ts.import_title);
                ui.label(ts.conflict.replace("{name}", &s.name));
                ui.horizontal(|ui| {
                    if ui.button(ts.replace).clicked() {
                        decision = Some(1);
                    }
                    if ui.button(ts.keep_both).clicked() {
                        decision = Some(2);
                    }
                    if ui.button(ts.cancel).clicked() {
                        decision = Some(0);
                    }
                });
            });
            if let Some(d) = decision {
                let mut s = self.import_queue.remove(0);
                let existing = self.styles.iter().find(|x| x.name == s.name && !x.builtin).map(|x| x.id.clone());
                match (d, existing) {
                    (1, Some(id)) => s.id = id,
                    (0, _) => return,
                    _ => s.name = self.unique_name(&s.name),
                }
                let name = s.name.clone();
                if self.store(s) {
                    self.notes.push(Note::Ok(format!("{}: {name}", ts.imported)));
                }
            }
        }

        if let Some(id) = self.confirm_delete.clone() {
            let name = self.styles.iter().find(|s| s.id == id).map(|s| s.name.clone()).unwrap_or_default();
            let mut decision = None;
            egui::Modal::new(egui::Id::unique("style-delete")).show(ctx, |ui| {
                ui.label(ts.delete_confirm.replace("{name}", &name));
                ui.horizontal(|ui| {
                    if ui.button(ts.delete).clicked() {
                        decision = Some(true);
                    }
                    if ui.button(ts.cancel).clicked() {
                        decision = Some(false);
                    }
                });
            });
            if let Some(yes) = decision {
                self.confirm_delete = None;
                if yes {
                    match style::delete(&id) {
                        Ok(()) => {
                            self.reload();
                            self.notes.push(Note::Ok(format!("{}: {name}", ts.deleted)));
                        }
                        Err(e) => self.notes.push(Note::Err(format!("{e:#}"))),
                    }
                }
            }
        }

        if let Some(mut r) = self.rename.take() {
            let mut decision = None;
            egui::Modal::new(egui::Id::unique("style-rename")).show(ctx, |ui| {
                ui.label(ts.name);
                let edit = ui.text_edit_singleline(&mut r.name);
                edit.request_focus();
                ui.horizontal(|ui| {
                    let ok = !r.name.trim().is_empty();
                    if ui.add_enabled(ok, egui::Button::new(ts.save)).clicked() || (ok && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                        decision = Some(true);
                    }
                    if ui.button(ts.cancel).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        decision = Some(false);
                    }
                });
            });
            match decision {
                Some(true) => {
                    if let Some(mut s) = self.styles.iter().find(|s| s.id == r.id).cloned() {
                        s.name = r.name.trim().to_string();
                        self.store(s);
                    }
                }
                Some(false) => {}
                None => self.rename = Some(r),
            }
        }
    }

    fn editor_window(&mut self, ctx: &egui::Context, data: &StampData, previewer: &Previewer) {
        let Some(mut ed) = self.editor.take() else { return };
        let ts = &t().style;
        let mut open = true;
        let mut action: Option<bool> = None; // Some(false) = save, Some(true) = save as new
        let mut cancel = false;
        let (mut pick, mut draw, mut from_pdf) = (false, false, false);
        egui::Window::new(ts.editor_title)
            .open(&mut open)
            .default_width(520.0)
            .default_height(680.0)
            .resizable(true)
            .collapsible(false)
            .scroll([false, true])
            .show(ctx, |ui| {
                let s = &mut ed.style;
                let (tex, clipped) = self.texture(ctx, "editor", s, data, s.size.w, s.size.h, 3.0);
                ui.vertical_centered(|ui| {
                    let max_w = ui.available_width().min(s.size.w * 2.0);
                    let size = vec2(max_w, max_w * s.size.h / s.size.w);
                    ui.add(egui::Image::from_texture(&tex).fit_to_exact_size(size).bg_fill(Color32::WHITE));
                    if clipped {
                        ui.colored_label(Color32::from_rgb(220, 140, 0), ts.clipped);
                    }
                });
                if ed.target.is_none() {
                    ui.label(RichText::new(ts.read_only_note).weak().small());
                }
                ui.separator();
                egui::Grid::new("style-editor").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label(ts.name);
                    ui.text_edit_singleline(&mut s.name);
                    ui.end_row();

                    ui.label(ts.size);
                    ui.horizontal(|ui| {
                        ui.add(egui::DragValue::new(&mut s.size.w).range(40.0..=600.0).speed(1.0).suffix(" ×"));
                        ui.add_enabled(s.shape != Shape::Seal, egui::DragValue::new(&mut s.size.h).range(20.0..=400.0).speed(1.0));
                    });
                    ui.end_row();

                    ui.label(ts.shape);
                    ui.horizontal_wrapped(|ui| {
                        let radius = match s.shape {
                            Shape::Rounded { radius } => radius,
                            _ => 6.0,
                        };
                        ui.radio_value(&mut s.shape, Shape::Rect, ts.shape_rect);
                        if ui.radio(matches!(s.shape, Shape::Rounded { .. }), ts.shape_rounded).clicked() {
                            s.shape = Shape::Rounded { radius };
                        }
                        ui.radio_value(&mut s.shape, Shape::Ellipse, ts.shape_ellipse);
                        ui.radio_value(&mut s.shape, Shape::Seal, ts.shape_seal);
                        ui.radio_value(&mut s.shape, Shape::None, ts.shape_none);
                        if let Shape::Rounded { radius } = &mut s.shape {
                            ui.add(egui::DragValue::new(radius).range(0.0..=60.0).speed(0.2).prefix(format!("{} ", ts.radius)));
                        }
                    });
                    ui.end_row();

                    ui.label(ts.colors);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(ts.palette).weak());
                            for (text, border, bg) in PALETTES {
                                let (r, g, b) = (text.0[0], text.0[1], text.0[2]);
                                let swatch = egui::Button::new("    ").fill(Color32::from_rgb(r, g, b));
                                if ui.add(swatch).on_hover_text(format!("{} / {}", text.hex(), border.hex())).clicked() {
                                    s.palette.text = text;
                                    s.palette.border = border;
                                    s.palette.background = bg;
                                }
                            }
                        });
                        ui.horizontal_wrapped(|ui| {
                            ui.label(ts.text_color);
                            ui.color_edit_button_srgb(&mut s.palette.text.0);
                            ui.label(ts.border_color);
                            ui.color_edit_button_srgb(&mut s.palette.border.0);
                            ui.label(ts.background_color);
                            ui.color_edit_button_srgb(&mut s.palette.background.0);
                        });
                        ui.add(egui::Slider::new(&mut s.palette.background_opacity, 0.0..=1.0).text(ts.opacity));
                    });
                    ui.end_row();

                    ui.label(ts.border);
                    ui.add_enabled_ui(s.shape != Shape::None, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.add(egui::DragValue::new(&mut s.border.width).range(0.0..=10.0).speed(0.05).suffix(" pt"));
                            ui.radio_value(&mut s.border.style, BorderStyle::Single, ts.single);
                            ui.radio_value(&mut s.border.style, BorderStyle::Double, ts.double);
                            ui.radio_value(&mut s.border.style, BorderStyle::Dashed, ts.dashed);
                        });
                    });
                    ui.end_row();

                    ui.label(ts.font);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            egui::ComboBox::from_id_salt("style-font")
                                .selected_text(match s.font.family {
                                    FontFamily::Sans => ts.sans,
                                    FontFamily::Serif => ts.serif,
                                    FontFamily::Mono => ts.mono,
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut s.font.family, FontFamily::Sans, ts.sans);
                                    ui.selectable_value(&mut s.font.family, FontFamily::Serif, ts.serif);
                                    ui.selectable_value(&mut s.font.family, FontFamily::Mono, ts.mono);
                                });
                            let mut auto = s.font.size.is_none();
                            if ui.checkbox(&mut auto, ts.auto_size).changed() {
                                s.font.size = if auto { None } else { Some(8.0) };
                            }
                            if let Some(pt) = &mut s.font.size {
                                ui.add(egui::DragValue::new(pt).range(3.0..=72.0).speed(0.1).suffix(" pt"));
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(ts.align).weak());
                            ui.radio_value(&mut s.font.align, Align::Left, ts.left);
                            ui.radio_value(&mut s.font.align, Align::Center, ts.center);
                            ui.radio_value(&mut s.font.align, Align::Right, ts.right);
                        });
                    });
                    ui.end_row();
                });

                if s.shape == Shape::Seal {
                    let seal = s.seal.get_or_insert_with(style::SealSpec::default);
                    ui.separator();
                    ui.strong(ts.shape_seal);
                    ui.label(RichText::new(ts.seal_hint).weak().small());
                    egui::Grid::new("seal-editor").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                        ui.label(ts.top_arc);
                        ui.add(egui::TextEdit::singleline(&mut seal.top).desired_width(f32::INFINITY));
                        ui.end_row();
                        ui.label(ts.bottom_arc);
                        ui.add(egui::TextEdit::singleline(&mut seal.bottom).desired_width(f32::INFINITY));
                        ui.end_row();
                        ui.label(ts.date_format);
                        ui.add(egui::TextEdit::singleline(&mut seal.date_format).desired_width(140.0));
                        ui.end_row();
                    });
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut seal.uppercase, ts.uppercase);
                        ui.checkbox(&mut seal.check, ts.center_check);
                    });
                }

                ui.separator();
                // The seal uses its arc texts instead of the field list.
                let fields_ui = s.shape != Shape::Seal;
                if fields_ui {
                ui.strong(ts.fields);
                ui.label(RichText::new(ts.placeholders).weak().small());
                let mut swap = None;
                let mut remove = None;
                let n = s.fields.len();
                for (i, f) in s.fields.iter_mut().enumerate() {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            if ui.add_enabled(i > 0, egui::Button::new("⬆").small()).on_hover_text(ts.up).clicked() {
                                swap = Some((i, i - 1));
                            }
                            if ui.add_enabled(i + 1 < n, egui::Button::new("⬇").small()).on_hover_text(ts.down).clicked() {
                                swap = Some((i, i + 1));
                            }
                            let mandatory = f.kind.mandatory();
                            let r = ui.add_enabled(!mandatory, egui::Checkbox::new(&mut f.enabled, field_name(f.kind)));
                            if mandatory {
                                r.on_disabled_hover_text(ts.mandatory);
                                ui.label(RichText::new("🔒").weak()).on_hover_text(ts.mandatory);
                            }
                            ui.checkbox(&mut f.bold, ts.bold);
                            let mut pct = f.scale * 100.0;
                            if ui.add(egui::DragValue::new(&mut pct).range(50.0..=300.0).speed(1.0).suffix(" %")).changed() {
                                f.scale = pct / 100.0;
                            }
                            if matches!(f.kind, FieldKind::Date | FieldKind::Reason | FieldKind::Location | FieldKind::Issuer | FieldKind::Contact) {
                                ui.checkbox(&mut f.prefix, ts.caption);
                            }
                            if f.kind == FieldKind::Custom && ui.small_button("🗑").on_hover_text(ts.remove).clicked() {
                                remove = Some(i);
                            }
                        });
                        match f.kind {
                            FieldKind::Date => {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(ts.date_format).weak());
                                    let mut fmt = f.format.clone().unwrap_or_else(|| style::DEFAULT_DATE_FORMAT.into());
                                    if ui.add(egui::TextEdit::singleline(&mut fmt).desired_width(180.0)).changed() {
                                        f.format = Some(fmt);
                                    }
                                    egui::ComboBox::from_id_salt(("date-presets", i)).selected_text("…").width(30.0).show_ui(ui, |ui| {
                                        for p in [style::DEFAULT_DATE_FORMAT, "%d.%m.%Y %H:%M", "%d.%m.%Y", "%Y-%m-%d %H:%M", "%d %B %Y"] {
                                            if ui.selectable_label(false, p).clicked() {
                                                f.format = Some(p.into());
                                            }
                                        }
                                    });
                                });
                            }
                            FieldKind::Custom => {
                                ui.add(egui::TextEdit::singleline(&mut f.text).desired_width(f32::INFINITY));
                            }
                            _ => {}
                        }
                    });
                }
                if let Some((a, b)) = swap {
                    s.fields.swap(a, b);
                }
                if let Some(i) = remove {
                    s.fields.remove(i);
                }
                if ui.button(ts.add_custom).clicked() {
                    let mut f = Field::new(FieldKind::Custom);
                    f.text = "{reason}".into();
                    s.fields.push(f);
                }
                }

                ui.separator();
                ui.strong(ts.image);
                ui.horizontal_wrapped(|ui| {
                    pick = ui.button(ts.from_file).clicked();
                    draw = ui.button(ts.draw).clicked();
                    from_pdf = ui
                        .add_enabled(previewer.available(), egui::Button::new(ts.from_pdf))
                        .on_disabled_hover_text(t().no_pdfium)
                        .clicked();
                    if s.image.is_some() && ui.button(ts.remove).clicked() {
                        s.image = None;
                    }
                });
                if let Some(img) = &mut s.image {
                    if img.is_empty() {
                        ui.label(RichText::new(ts.no_image).weak());
                    } else if let Some((w, h)) = stamp::picture_size(img) {
                        ui.label(RichText::new(ts.image_size.replace("{w}", &w.to_string()).replace("{h}", &h.to_string())).weak().small());
                    }
                    ui.horizontal_wrapped(|ui| {
                        ui.radio_value(&mut img.position, ImagePosition::Left, ts.left);
                        ui.radio_value(&mut img.position, ImagePosition::Right, ts.right);
                        ui.radio_value(&mut img.position, ImagePosition::Top, ts.pos_top);
                        ui.radio_value(&mut img.position, ImagePosition::Background, ts.pos_background);
                    });
                    ui.add(egui::Slider::new(&mut img.opacity, 0.05..=1.0).text(ts.opacity));
                    ui.horizontal(|ui| {
                        let mut on = img.remove_background.is_some();
                        if ui.checkbox(&mut on, ts.remove_bg).changed() {
                            img.remove_background = on.then_some(0.9);
                        }
                        if let Some(th) = &mut img.remove_background {
                            ui.add(egui::Slider::new(th, 0.5..=0.99).fixed_decimals(2));
                        }
                    });
                }

                ui.separator();
                ui.checkbox(&mut s.locked, ts.locked_opt);
                s.normalize();
                ui.horizontal(|ui| {
                    if ui.button(ts.cancel).clicked() {
                        cancel = true;
                    }
                    let ok = !s.name.trim().is_empty();
                    if ui.add_enabled(ok, egui::Button::new(ts.save_as)).clicked() {
                        action = Some(true);
                    }
                    if ui.add_enabled(ok && ed.target.is_some(), egui::Button::new(RichText::new(ts.save).strong())).clicked() {
                        action = Some(false);
                    }
                });
            });

        if pick || draw || from_pdf {
            self.editor = Some(ed);
            if pick {
                self.pick_picture(previewer);
            } else if draw {
                self.pad = Some(DrawPad::new());
            } else {
                self.open_sig_pick(ctx, previewer);
            }
            return;
        }
        match action {
            Some(as_new) => {
                let mut s = ed.style;
                s.builtin = false;
                s.name = s.name.trim().to_string();
                match (as_new, ed.target) {
                    (false, Some(id)) => s.id = id,
                    _ => {
                        s.id = style::new_id();
                        s.name = self.unique_name(&s.name);
                    }
                }
                let name = s.name.clone();
                if self.store(s) {
                    self.notes.push(Note::Ok(format!("{}: {name}", ts.saved)));
                }
            }
            None if open && !cancel => self.editor = Some(ed),
            None => {}
        }
    }
}
