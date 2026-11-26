# Design: signature stamp appearance (shape, style, own and imported graphics)

Status: implemented (phases 1–5) · Target: v0.2.0 · Epic #27 (phases #22–#26)

Decisions: the stamp stays a raster image; **"Digitally signed by {name}" is mandatory** (cannot be removed); corporate palette `#1A3E8C` / `#00A19A`.

## 1. Goals

- Choose the **shape** of the visible stamp: rectangle, rounded rectangle, ellipse, round seal with text along the circle, or no border.
- Choose the **style**: colours (corporate look, several palettes), border, background, font, which fields are shown and in what order.
- Use **graphics that come from outside the app**:
  - a handwritten signature as an image (scan or photo),
  - a signature drawn with the mouse or pen inside the app,
  - a company logo or scanned company seal,
  - appearance templates from other applications,
  - the look of an existing signature in another signed PDF.
- **Save** styles under a name and share them through Import/Export of `.json` files.
- The stamp stays an **image** inside the PDF (raster, as today): it looks the same in every viewer and no fonts are embedded.

Non-goals:
- Text that can be selected inside the stamp.
- Editing other people's signatures.
- Any change to the cryptographic signature. The appearance is purely visual; the signer is always determined by the certificate.

## 2. UX

### 2.1 Right panel: "Stamp appearance" (replaces "Visible stamp")

```
┌ Stamp appearance ────────────────────────────┐
│ [x] Place a visible stamp                    │
│                                              │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐  ▸  │   <- gallery: live thumbnails
│  │Box  │ │Min. │ │Badge│ │ (●) │ │✍ img│     │      (built-in + mine)
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘     │
│  Style: PHOENIX Corporate ▾   [Edit…] [⋯]    │   <- ⋯ = Duplicate, Rename, Export,
│                                              │        Import…, Delete, Set as default
│  Click or drag on the page; drag the corners │
│  to resize (Shift keeps proportions).        │
│  [Reset positions] [Apply position to all]   │
└──────────────────────────────────────────────┘
```

- Clicking a thumbnail applies the style immediately to the preview of the page.
- The last style used becomes the default and is remembered between sessions.
- The width/height sliders are replaced by **corner handles** on the stamp in the page preview. Shift keeps the proportions; the round seal always keeps them.
- Document context menu: "Use another style for this document…". The document card then shows a badge with the style name.

### 2.2 Style editor (dialog, live preview)

```
┌ Edit style: PHOENIX Corporate ───────────────────────────────────────────┐
│ Shape    (•) Rectangle ( ) Rounded [r=6] ( ) Ellipse ( ) Seal ( ) None     │ ┌──────────────┐
│ Colours  Palette: [■ Corporate] [■ Ink] [■ Green] [■ Red] [■ Custom…]      │ │              │
│          Text ■  Border ■  Background ■  opacity [━━━●━] 60%               │ │ live preview │
│ Border   width [1.2] pt   ( ) single (•) double   ( ) dashed               │ │ at real size │
│ Font     [Segoe UI ▾]  size (•) auto ( ) [9] pt   alignment [left ▾]       │ │ + 2× zoom    │
│ Fields   ☰ [x] "Digitally signed by"                                       │ │              │
│ (drag)   ☰ [x] Name                      bold, 145%                        │ └──────────────┘
│          ☰ [x] Date        format [dd.MM.yyyy HH:mm ▾]                     │
│          ☰ [ ] Reason   ☰ [ ] Location   ☰ [ ] Issuer   ☰ [ ] Contact      │
│          ☰ [ ] Custom text [______________]  (+ add)                       │
│ Image    [None ▾]  ← From file… / Draw… / From signed PDF… / Remove        │
│          position (•) left ( ) right ( ) top ( ) behind the text           │
│          opacity [━━━━●] 100%   [x] remove white background [━●━] 92%      │
│ Seal     top arc [ {name} ]  bottom arc [ {date} ]  centre [image ▾]       │
│                                       [Cancel] [Save as…] [Save]           │
└──────────────────────────────────────────────────────────────────────────┘
```

- Every change is visible immediately: in the editor preview, and also on the page behind the dialog.
- Rows that don't apply are hidden (for example the "Seal" row unless the shape is a seal).
- **Placeholders** such as `{name}`, `{date}`, `{reason}`, `{location}`, `{issuer}` and `{contact}` work in every text field.
- Validation: if a line doesn't fit, auto-size shrinks it (as today). With a fixed size, a warning appears: "Text is cut off".

### 2.3 Image sources

| Source | UX | Notes |
|---|---|---|
| **From file** | Pick PNG / JPG / SVG / PDF (first page) | A scanned signature gets **"Remove white background"** (threshold slider) and **automatic trimming** of empty margins |
| **Draw** | Dialog with a canvas, pen thickness and colour, Undo, Clear, "Smooth the line"; Enter = Save | Stored as a transparent PNG, trimmed to the content |
| **Logo / company seal** | Same as "From file", with position "behind the text" (watermark) or "top"; for the seal shape: "centre" | |
| **From signed PDF** | Pick a PDF → list of the signatures in it (thumbnail, signer, page) → choose one → it becomes the style's image | ⚠ Shows "Use only appearances you own or are authorised to use." Needs pdfium (otherwise the button is disabled, with a hint) |
| **From other apps** | No proprietary configuration formats are read. Adobe "imported graphic" = PDF/image → **From file**. B-Trust / Evrotrust / Adobe appearances in an already signed document → **From signed PDF** | Their configuration formats are closed, undocumented and change between versions. Importing the result covers 100 % of cases |

### 2.4 Built-in styles (gallery)

1. **Classic**: today's look (rectangle, blue ink, 3–5 lines).
2. **Minimal**: no border; name and date only.
3. **Badge**: rounded rectangle with a coloured background and white text.
4. **Seal**: circle; top arc = name, bottom arc = date, centre = ✓ or logo.
5. **Handwritten**: image on the left, name and date on the right (empty until an image is added; opens "Draw…").
6. **Corporate**: logo on top, corporate palette (`#1A3E8C` / `#00A19A`, adjustable).

Built-in styles are read-only. "Edit" on one of them first makes a copy ("Classic (copy)").

### 2.5 Sharing

- `⋯ → Export…` writes one `.json` file per style. Images are embedded as base64 PNG, so the file is self-contained.
- `⋯ → Import…` accepts `.json` files. On a name clash it asks: Replace / Keep both.
- Corporate distribution: an exported file with `"locked": true` imports as read-only (only Duplicate is allowed), so the corporate look doesn't drift.

## 3. Data model (`styles/<id>.json`)

```json
{
  "version": 1,
  "id": "6f1c…",
  "name": "PHOENIX Corporate",
  "locked": false,
  "shape": { "kind": "rounded", "radius": 6 },
  "size":  { "w": 190, "h": 62, "keep_aspect": false },
  "palette": { "text": "#1A3E8C", "border": "#1A3E8C", "background": "#E6EEFF", "background_opacity": 0.6 },
  "border": { "width": 1.2, "style": "double" },
  "font":   { "family": "Segoe UI", "size": "auto", "align": "left" },
  "fields": [
    { "kind": "label" },
    { "kind": "name", "bold": true, "scale": 1.45 },
    { "kind": "date", "format": "%d.%m.%Y %H:%M" },
    { "kind": "custom", "text": "{reason}" }
  ],
  "image": { "png_base64": "…", "position": "left", "opacity": 1.0 },
  "seal":  { "top": "{name}", "bottom": "{date}", "center": "image" }
}
```

Location:
- Windows: `%APPDATA%\DocSigner\styles\`
- Linux: `$XDG_CONFIG_HOME/DocSigner/styles/`

The default style goes into `settings.txt` as `style=<id>`.

## 4. Technical design

- **One renderer**: `tiny-skia` (pure Rust) replaces the current alpha mask.
  - Shapes, double and dashed borders, transparent backgrounds and image compositing all go through it.
  - Text uses `ab_glyph` outlines converted to `tiny-skia` paths, so glyphs can be **rotated** along an arc for the seal.
  - Output is RGBA at 4× resolution, as today.
- **PDF**: the RGB image plus its `/SMask` (alpha). The appearance stream (`/AP /N`) and incremental update stay as they are. Only `stamp.rs` and the image part of `pdf.rs` change.
- **Images**:
  - the `image` crate (PNG/JPEG; already a transitive dependency of pdfium-render),
  - `resvg` for SVG,
  - pdfium for PDF graphics.
  - "Remove background": white below the threshold becomes transparent, with soft edges. Trimming uses the alpha bounding box.
- **Drawing**: egui collects the points; smoothing with Catmull-Rom; `tiny-skia` draws the stroke with round caps.
- **From signed PDF**: lopdf finds the `/FT /Sig` widgets and their `/AP /N` streams. The appearance XObject is copied into a temporary one-page PDF the size of its `/BBox` and rendered with pdfium on a transparent background, so the page underneath is not included.
- **Serialisation**: `serde` / `serde_json`, plus `base64`.
- **New dependencies**: `tiny-skia`, `resvg`, `image` (explicitly), `serde`, `serde_json`, `base64`. All MIT/Apache-compatible.

## 5. Phases (one PR each, `feature/*` → `dev`)

| Phase | Contents | Acceptance |
|---|---|---|
| 1 | `tiny-skia` renderer; RGBA in the PDF; style model, JSON storage; built-in styles 1–3 and 6; gallery; editor (shape rect/rounded/ellipse/none, palette, border, font, fields, placeholders); Import/Export, `locked` | The existing "Classic" look matches today's pixel for pixel ±; CI validation stays green |
| 2 | Images: from file (PNG/JPG/SVG/PDF), background removal, trimming, positions; drawing pad; style 5 | A scanned signature on a white background ends up transparent |
| 3 | Round seal: text along an arc, centre image or ✓; style 4 | Text does not overlap at any length (auto-fit to the arc) |
| 4 | From signed PDF (list of signatures, rendering the appearance alone) | Works with PDFs signed by Adobe, B-Trust and this app |
| 5 | Resize handles on the page; style per document; i18n EN/BG/DE/ES for everything | — |

## 6. Risks

- **Misuse of someone else's appearance** (copying a handwritten signature from a PDF). Mitigations: an explicit warning, and the cryptographic signature always shows the real signer. Decision: the label "Digitally signed by" and the name are mandatory in every style.
- **pdfium is optional.** PDF import and "From signed PDF" are disabled without it, with a clear explanation.
- **File size.** Images are limited to 1500 px on the longer side, and the stamp is compressed with Flate as today.
