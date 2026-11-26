//! UI translations (EN / BG / DE / ES) and language selection.
//!
//! Startup language: the user's saved choice, otherwise the OS UI language
//! (Windows LANGID / the `LANG` environment variable), falling back to English
//! when the OS uses a language that is not supported.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    Bg,
    De,
    Es,
}

impl Lang {
    pub const ALL: [Lang; 4] = [Lang::En, Lang::Bg, Lang::De, Lang::Es];

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Bg => "bg",
            Lang::De => "de",
            Lang::Es => "es",
        }
    }

    pub fn from_code(code: &str) -> Option<Lang> {
        Lang::ALL.into_iter().find(|l| l.code().eq_ignore_ascii_case(code.trim()))
    }

    pub fn native_name(self) -> &'static str {
        tr(self).name
    }

    /// Maps a Windows LANGID (primary language = low 10 bits) to a supported language.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn from_langid(id: u16) -> Lang {
        match id & 0x3ff {
            0x02 => Lang::Bg,
            0x07 => Lang::De,
            0x0a => Lang::Es,
            _ => Lang::En,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set(lang: Lang) {
    CURRENT.store(lang as u8, Ordering::Relaxed);
}

pub fn current() -> Lang {
    Lang::ALL[CURRENT.load(Ordering::Relaxed) as usize]
}

/// Strings for the current language.
pub fn t() -> &'static Tr {
    tr(current())
}

pub fn tr(lang: Lang) -> &'static Tr {
    match lang {
        Lang::En => &EN,
        Lang::Bg => &BG,
        Lang::De => &DE,
        Lang::Es => &ES,
    }
}

pub fn system() -> Lang {
    #[cfg(windows)]
    {
        Lang::from_langid(unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() })
    }
    #[cfg(not(windows))]
    {
        for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(v) = std::env::var(var) {
                let code = v.split(['.', '_']).next().unwrap_or_default();
                if let Some(l) = Lang::from_code(code) {
                    return l;
                }
            }
        }
        Lang::En
    }
}

fn settings_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("DocSigner").join("settings.txt"))
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME")?;
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from(home).join(".config"));
        Some(base.join("DocSigner").join("settings.txt"))
    }
}

fn saved() -> Option<Lang> {
    let text = std::fs::read_to_string(settings_path()?).ok()?;
    text.lines().find_map(|l| l.strip_prefix("lang=")).and_then(Lang::from_code)
}

pub fn initial() -> Lang {
    saved().unwrap_or_else(system)
}

pub fn save(lang: Lang) {
    if let Some(p) = settings_path() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(p, format!("lang={}\n", lang.code()));
    }
}

/// `{n}`, `{p}`, `{cert}` placeholders are replaced by the caller.
pub struct Tr {
    pub name: &'static str,
    pub language: &'static str,
    pub window_title: &'static str,

    pub pdfium_missing: &'static str,
    pub stamp_font_fallback: &'static str,
    pub no_certs: &'static str,
    #[cfg_attr(windows, allow(dead_code))]
    pub no_certs_hint: &'static str,
    pub certs_error: &'static str,
    pub skipped_not_pdf: &'static str,
    pub pdf_filter: &'static str,
    pub pick_title: &'static str,
    pub signing_log: &'static str,
    pub signed_log: &'static str,

    pub docs_heading: &'static str,
    pub clear: &'static str,
    pub add: &'static str,
    pub drop_hint: &'static str,
    pub no_docs: &'static str,
    pub select_all: &'static str,
    pub remove_tip: &'static str,
    pub pages: &'static str,
    pub already_signed: &'static str,
    pub placed: &'static str,
    pub open: &'static str,
    pub reveal: &'static str,

    pub cert_heading: &'static str,
    pub choose: &'static str,
    pub until: &'static str,
    pub refresh_tip: &'static str,
    pub show_expired: &'static str,
    pub issuer: &'static str,
    pub valid: &'static str,
    pub expired: &'static str,
    pub purpose: &'static str,
    pub purpose_doc: &'static str,
    pub purpose_general: &'static str,
    pub thumbprint: &'static str,

    pub meta_heading: &'static str,
    pub reason: &'static str,
    pub reason_hint: &'static str,
    pub location: &'static str,
    pub location_hint: &'static str,
    pub contact: &'static str,
    pub contact_hint: &'static str,

    pub stamp_heading: &'static str,
    pub stamp_enable: &'static str,
    pub stamp_hint: &'static str,
    pub width: &'static str,
    pub height: &'static str,
    pub reset_pos: &'static str,
    pub apply_all: &'static str,
    pub apply_all_tip: &'static str,

    pub output_heading: &'static str,
    pub output_new: &'static str,
    pub suffix_label: &'static str,
    pub default_suffix: &'static str,
    pub output_overwrite: &'static str,
    pub open_folder: &'static str,
    pub sign_btn: &'static str,
    pub signing_btn: &'static str,
    pub why_cert: &'static str,
    pub why_docs: &'static str,
    pub why_suffix: &'static str,
    pub pin_hint: &'static str,

    pub preview_empty: &'static str,
    pub cannot_open: &'static str,
    pub page_of: &'static str,
    pub preview_unavailable: &'static str,
    pub no_pdfium: &'static str,
    pub default_pos: &'static str,
    pub stamp_on_page: &'static str,
    pub log_heading: &'static str,
    pub drop_overlay: &'static str,
    pub sample_name: &'static str,

    pub stamp_signed_by: &'static str,
    pub stamp_date: &'static str,

    pub err_store: &'static str,
    pub err_cert_not_found: &'static str,
    pub err_key_alg: &'static str,
    pub err_no_key: &'static str,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub err_not_cng: &'static str,
    pub err_sign_refused: &'static str,
    pub err_invalid_pdf: &'static str,
    #[cfg_attr(windows, allow(dead_code))]
    pub err_invalid_cert: &'static str,
    pub err_encrypted: &'static str,
    pub err_no_pages: &'static str,
    pub err_pdf_structure: &'static str,
    pub err_too_large: &'static str,
    pub err_sig_too_big: &'static str,
}

pub static EN: Tr = Tr {
    name: "English",
    language: "Language",
    window_title: "Doc Signer – PDF signing",
    pdfium_missing: "pdfium not found (pdfium.dll on Windows, libpdfium.so on Linux) – pages are shown without content (stamp placement still works).",
    stamp_font_fallback: "No system font (DejaVu/Noto/Liberation) found for the stamp – using the built-in font.",
    no_certs: "No personal certificates with a private key found.",
    no_certs_hint: "Windows: certificates come from the store CurrentUser\\My. Linux: certificates come from the folder {d} (PKCS#12 .p12/.pfx files, or .crt/.pem + .key pairs; key passphrase via the DOC_SIGNER_PASS env var or a .pass file next to the key, chmod 600).",
    certs_error: "Error reading certificates",
    skipped_not_pdf: "Skipped (not a PDF)",
    pdf_filter: "PDF documents",
    pick_title: "Choose documents to sign",
    signing_log: "Signing {n} document(s) with “{cert}”…",
    signed_log: "Signed",
    docs_heading: "Documents",
    clear: "Clear",
    add: "➕ Add…",
    drop_hint: "Drop PDF files here or click “Add”.",
    no_docs: "No documents selected",
    select_all: "Select all",
    remove_tip: "Remove from list",
    pages: "{n} p.",
    already_signed: "already has {n} signature(s)",
    placed: "stamp positioned",
    open: "Open",
    reveal: "Show in folder",
    cert_heading: "Certificate",
    choose: "— choose —",
    until: "until",
    refresh_tip: "Refresh certificate list",
    show_expired: "Show expired certificates too",
    issuer: "Issuer",
    valid: "Valid",
    expired: "(expired)",
    purpose: "Purpose",
    purpose_doc: "Document signing ★",
    purpose_general: "General",
    thumbprint: "Thumbprint",
    meta_heading: "Signature details",
    reason: "Reason",
    reason_hint: "e.g. I approve this document",
    location: "Location",
    location_hint: "e.g. Sofia",
    contact: "Contact",
    contact_hint: "email or phone (optional)",
    stamp_heading: "Visible stamp",
    stamp_enable: "Place a visible stamp on the page",
    stamp_hint: "Click or drag on the preview to place the stamp. Default: bottom right of the last page.",
    width: "width (pt)",
    height: "height (pt)",
    reset_pos: "Reset positions",
    apply_all: "Apply position to all",
    apply_all_tip: "Same page (or the last one if there are fewer) and same spot",
    output_heading: "Output",
    output_new: "New file next to the original",
    suffix_label: "suffix",
    default_suffix: " - signed",
    output_overwrite: "Overwrite the original",
    open_folder: "Open folder after signing",
    sign_btn: "✍  Sign ({n})",
    signing_btn: "Signing…",
    why_cert: "Choose a certificate.",
    why_docs: "Tick at least one document.",
    why_suffix: "Enter a suffix for the new file.",
    pin_hint: "A PIN prompt may appear for smart cards.",
    preview_empty: "Choose or add a document to see the preview",
    cannot_open: "The document cannot be opened:",
    page_of: "Page {p} of {n}",
    preview_unavailable: "Preview not available",
    no_pdfium: "No preview (pdfium library missing)",
    default_pos: "default position",
    stamp_on_page: "The stamp is on page {n}",
    log_heading: "Log",
    drop_overlay: "Drop the PDF files here",
    sample_name: "First Last",
    stamp_signed_by: "Digitally signed by",
    stamp_date: "Date",
    err_store: "Cannot open the personal certificate store",
    err_cert_not_found: "Certificate not found in the store",
    err_key_alg: "Unsupported key algorithm",
    err_no_key: "No access to the certificate's private key",
    err_not_cng: "The key is not a CNG key",
    err_sign_refused: "Signing with the key was refused",
    err_invalid_pdf: "Invalid PDF",
    err_invalid_cert: "Invalid certificate file (no certificate found)",
    err_encrypted: "Encrypted (password-protected) PDF files are not supported",
    err_no_pages: "The PDF has no pages",
    err_pdf_structure: "Damaged PDF structure",
    err_too_large: "The file is too large",
    err_sig_too_big: "The signature does not fit in the reserved space",
};

pub static BG: Tr = Tr {
    name: "Български",
    language: "Език",
    window_title: "Doc Signer – подписване на PDF",
    pdfium_missing: "pdfium не е намерен (pdfium.dll под Windows, libpdfium.so под Linux) – страниците се показват без съдържание (поставянето на печат работи).",
    stamp_font_fallback: "Не е намерен системен шрифт (DejaVu/Noto/Liberation) за печата – използва се вграденият шрифт.",
    no_certs: "Няма намерени лични сертификати с частен ключ.",
    no_certs_hint: "Windows: сертификатите идват от хранилището CurrentUser\\My. Linux: сертификатите идват от папката {d} (файлове PKCS#12 .p12/.pfx или двойки .crt/.pem + .key; парола на ключа през променливата DOC_SIGNER_PASS или .pass файл до ключа, chmod 600).",
    certs_error: "Грешка при четене на сертификатите",
    skipped_not_pdf: "Пропуснат (не е PDF)",
    pdf_filter: "PDF документи",
    pick_title: "Избери документи за подписване",
    signing_log: "Подписвам {n} документа със „{cert}“…",
    signed_log: "Подписан",
    docs_heading: "Документи",
    clear: "Изчисти",
    add: "➕ Добави…",
    drop_hint: "Пусни PDF файлове тук или натисни „Добави“.",
    no_docs: "Няма избрани документи",
    select_all: "Избери всички",
    remove_tip: "Премахни от списъка",
    pages: "{n} стр.",
    already_signed: "вече има {n} подпис(а)",
    placed: "печатът е позициониран",
    open: "Отвори",
    reveal: "Покажи в папката",
    cert_heading: "Сертификат",
    choose: "— избери —",
    until: "до",
    refresh_tip: "Обнови списъка със сертификати",
    show_expired: "Покажи и изтекли сертификати",
    issuer: "Издател",
    valid: "Валиден",
    expired: "(изтекъл)",
    purpose: "Предназначение",
    purpose_doc: "Подписване на документи ★",
    purpose_general: "Общо",
    thumbprint: "Отпечатък",
    meta_heading: "Данни за подписа",
    reason: "Причина",
    reason_hint: "напр. Одобрявам документа",
    location: "Място",
    location_hint: "напр. София",
    contact: "Контакт",
    contact_hint: "имейл или телефон (по желание)",
    stamp_heading: "Видим печат",
    stamp_enable: "Постави видим печат върху страницата",
    stamp_hint: "Щракни или влачи върху прегледа, за да поставиш печата. Без избор – долу вдясно на последната страница.",
    width: "ширина (pt)",
    height: "височина (pt)",
    reset_pos: "Нулирай позициите",
    apply_all: "Приложи позицията за всички",
    apply_all_tip: "Същата страница (или последната, ако няма толкова) и същото място",
    output_heading: "Резултат",
    output_new: "Нов файл до оригинала",
    suffix_label: "наставка",
    default_suffix: " - подписан",
    output_overwrite: "Презапиши оригинала",
    open_folder: "Отвори папката след подписване",
    sign_btn: "✍  Подпиши ({n})",
    signing_btn: "Подписване…",
    why_cert: "Избери сертификат.",
    why_docs: "Отметни поне един документ.",
    why_suffix: "Въведи наставка за новия файл.",
    pin_hint: "При смарт карта може да се появи прозорец за PIN.",
    preview_empty: "Избери или добави документ, за да видиш прегледа",
    cannot_open: "Документът не може да се отвори:",
    page_of: "Страница {p} от {n}",
    preview_unavailable: "Прегледът не е наличен",
    no_pdfium: "Без преглед (липсва библиотеката pdfium)",
    default_pos: "позиция по подразбиране",
    stamp_on_page: "Печатът е на страница {n}",
    log_heading: "Журнал",
    drop_overlay: "Пусни PDF файловете тук",
    sample_name: "Име Фамилия",
    stamp_signed_by: "Цифрово подписан от",
    stamp_date: "Дата",
    err_store: "Не мога да отворя хранилището с личните сертификати",
    err_cert_not_found: "Сертификатът не е намерен в хранилището",
    err_key_alg: "Неподдържан алгоритъм на ключа",
    err_no_key: "Нямам достъп до частния ключ на сертификата",
    err_not_cng: "Ключът не е CNG ключ",
    err_sign_refused: "Подписването с ключа беше отказано",
    err_invalid_pdf: "Невалиден PDF",
    err_invalid_cert: "Невалиден файл със сертификат (няма сертификат)",
    err_encrypted: "Криптирани (защитени с парола) PDF файлове не се поддържат",
    err_no_pages: "PDF файлът няма страници",
    err_pdf_structure: "Повредена структура на PDF",
    err_too_large: "Файлът е прекалено голям",
    err_sig_too_big: "Подписът не се побира в резервираното място",
};

pub static DE: Tr = Tr {
    name: "Deutsch",
    language: "Sprache",
    window_title: "Doc Signer – PDF-Signatur",
    pdfium_missing: "pdfium nicht gefunden (pdfium.dll unter Windows, libpdfium.so unter Linux) – Seiten werden ohne Inhalt angezeigt (Stempelplatzierung funktioniert weiterhin).",
    stamp_font_fallback: "Keine Systemschrift (DejaVu/Noto/Liberation) für den Stempel gefunden – die integrierte Schrift wird verwendet.",
    no_certs: "Keine persönlichen Zertifikate mit privatem Schlüssel gefunden.",
    no_certs_hint: "Windows: Zertifikate kommen aus dem Speicher CurrentUser\\My. Linux: Zertifikate kommen aus dem Ordner {d} (PKCS#12 .p12/.pfx-Dateien oder .crt/.pem + .key-Paare; Schlüssel-Passphrase über die Umgebungsvariable DOC_SIGNER_PASS oder eine .pass-Datei neben dem Schlüssel, chmod 600).",
    certs_error: "Fehler beim Lesen der Zertifikate",
    skipped_not_pdf: "Übersprungen (keine PDF)",
    pdf_filter: "PDF-Dokumente",
    pick_title: "Zu signierende Dokumente auswählen",
    signing_log: "Signiere {n} Dokument(e) mit „{cert}“…",
    signed_log: "Signiert",
    docs_heading: "Dokumente",
    clear: "Leeren",
    add: "➕ Hinzufügen…",
    drop_hint: "PDF-Dateien hierher ziehen oder „Hinzufügen“ klicken.",
    no_docs: "Keine Dokumente ausgewählt",
    select_all: "Alle auswählen",
    remove_tip: "Aus der Liste entfernen",
    pages: "{n} S.",
    already_signed: "bereits {n} Signatur(en)",
    placed: "Stempel positioniert",
    open: "Öffnen",
    reveal: "Im Ordner anzeigen",
    cert_heading: "Zertifikat",
    choose: "— auswählen —",
    until: "bis",
    refresh_tip: "Zertifikatsliste aktualisieren",
    show_expired: "Auch abgelaufene Zertifikate anzeigen",
    issuer: "Aussteller",
    valid: "Gültig",
    expired: "(abgelaufen)",
    purpose: "Verwendung",
    purpose_doc: "Dokumentsignatur ★",
    purpose_general: "Allgemein",
    thumbprint: "Fingerabdruck",
    meta_heading: "Signaturdetails",
    reason: "Grund",
    reason_hint: "z. B. Ich genehmige das Dokument",
    location: "Ort",
    location_hint: "z. B. Mannheim",
    contact: "Kontakt",
    contact_hint: "E-Mail oder Telefon (optional)",
    stamp_heading: "Sichtbarer Stempel",
    stamp_enable: "Sichtbaren Stempel auf der Seite platzieren",
    stamp_hint: "Zum Platzieren in die Vorschau klicken oder ziehen. Standard: unten rechts auf der letzten Seite.",
    width: "Breite (pt)",
    height: "Höhe (pt)",
    reset_pos: "Positionen zurücksetzen",
    apply_all: "Position für alle übernehmen",
    apply_all_tip: "Gleiche Seite (bzw. die letzte, falls weniger Seiten) und gleiche Stelle",
    output_heading: "Ausgabe",
    output_new: "Neue Datei neben dem Original",
    suffix_label: "Suffix",
    default_suffix: " - signiert",
    output_overwrite: "Original überschreiben",
    open_folder: "Ordner nach dem Signieren öffnen",
    sign_btn: "✍  Signieren ({n})",
    signing_btn: "Signiere…",
    why_cert: "Zertifikat auswählen.",
    why_docs: "Mindestens ein Dokument ankreuzen.",
    why_suffix: "Suffix für die neue Datei eingeben.",
    pin_hint: "Bei Smartcards kann eine PIN-Abfrage erscheinen.",
    preview_empty: "Dokument auswählen oder hinzufügen, um die Vorschau zu sehen",
    cannot_open: "Das Dokument kann nicht geöffnet werden:",
    page_of: "Seite {p} von {n}",
    preview_unavailable: "Vorschau nicht verfügbar",
    no_pdfium: "Keine Vorschau (pdfium-Bibliothek fehlt)",
    default_pos: "Standardposition",
    stamp_on_page: "Der Stempel ist auf Seite {n}",
    log_heading: "Protokoll",
    drop_overlay: "PDF-Dateien hier ablegen",
    sample_name: "Vorname Nachname",
    stamp_signed_by: "Digital signiert von",
    stamp_date: "Datum",
    err_store: "Persönlicher Zertifikatsspeicher kann nicht geöffnet werden",
    err_cert_not_found: "Zertifikat wurde im Speicher nicht gefunden",
    err_key_alg: "Nicht unterstützter Schlüsselalgorithmus",
    err_no_key: "Kein Zugriff auf den privaten Schlüssel des Zertifikats",
    err_not_cng: "Der Schlüssel ist kein CNG-Schlüssel",
    err_sign_refused: "Signieren mit dem Schlüssel wurde abgelehnt",
    err_invalid_pdf: "Ungültige PDF",
    err_invalid_cert: "Ungültige Zertifikatsdatei (kein Zertifikat gefunden)",
    err_encrypted: "Verschlüsselte (passwortgeschützte) PDF-Dateien werden nicht unterstützt",
    err_no_pages: "Die PDF hat keine Seiten",
    err_pdf_structure: "Beschädigte PDF-Struktur",
    err_too_large: "Die Datei ist zu groß",
    err_sig_too_big: "Die Signatur passt nicht in den reservierten Platz",
};

pub static ES: Tr = Tr {
    name: "Español",
    language: "Idioma",
    window_title: "Doc Signer – firma de PDF",
    pdfium_missing: "No se encontró pdfium (pdfium.dll en Windows, libpdfium.so en Linux): las páginas se muestran sin contenido (la colocación del sello sigue funcionando).",
    stamp_font_fallback: "No se encontró una fuente del sistema (DejaVu/Noto/Liberation) para el sello: se usa la fuente integrada.",
    no_certs: "No se encontraron certificados personales con clave privada.",
    no_certs_hint: "Windows: los certificados provienen del almacén CurrentUser\\My. Linux: los certificados provienen de la carpeta {d} (archivos PKCS#12 .p12/.pfx o pares .crt/.pem + .key; passphrase de la clave mediante la variable DOC_SIGNER_PASS o un archivo .pass junto a la clave, chmod 600).",
    certs_error: "Error al leer los certificados",
    skipped_not_pdf: "Omitido (no es un PDF)",
    pdf_filter: "Documentos PDF",
    pick_title: "Elegir documentos para firmar",
    signing_log: "Firmando {n} documento(s) con «{cert}»…",
    signed_log: "Firmado",
    docs_heading: "Documentos",
    clear: "Limpiar",
    add: "➕ Añadir…",
    drop_hint: "Arrastra archivos PDF aquí o pulsa «Añadir».",
    no_docs: "No hay documentos seleccionados",
    select_all: "Seleccionar todo",
    remove_tip: "Quitar de la lista",
    pages: "{n} pág.",
    already_signed: "ya tiene {n} firma(s)",
    placed: "sello colocado",
    open: "Abrir",
    reveal: "Mostrar en carpeta",
    cert_heading: "Certificado",
    choose: "— elegir —",
    until: "hasta",
    refresh_tip: "Actualizar la lista de certificados",
    show_expired: "Mostrar también certificados caducados",
    issuer: "Emisor",
    valid: "Válido",
    expired: "(caducado)",
    purpose: "Uso",
    purpose_doc: "Firma de documentos ★",
    purpose_general: "General",
    thumbprint: "Huella digital",
    meta_heading: "Datos de la firma",
    reason: "Motivo",
    reason_hint: "p. ej. Apruebo el documento",
    location: "Lugar",
    location_hint: "p. ej. Madrid",
    contact: "Contacto",
    contact_hint: "correo o teléfono (opcional)",
    stamp_heading: "Sello visible",
    stamp_enable: "Colocar un sello visible en la página",
    stamp_hint: "Haz clic o arrastra en la vista previa para colocar el sello. Por defecto: abajo a la derecha de la última página.",
    width: "ancho (pt)",
    height: "alto (pt)",
    reset_pos: "Restablecer posiciones",
    apply_all: "Aplicar posición a todos",
    apply_all_tip: "Misma página (o la última si hay menos) y mismo lugar",
    output_heading: "Resultado",
    output_new: "Nuevo archivo junto al original",
    suffix_label: "sufijo",
    default_suffix: " - firmado",
    output_overwrite: "Sobrescribir el original",
    open_folder: "Abrir la carpeta después de firmar",
    sign_btn: "✍  Firmar ({n})",
    signing_btn: "Firmando…",
    why_cert: "Elige un certificado.",
    why_docs: "Marca al menos un documento.",
    why_suffix: "Introduce un sufijo para el nuevo archivo.",
    pin_hint: "Con tarjetas inteligentes puede aparecer una solicitud de PIN.",
    preview_empty: "Elige o añade un documento para ver la vista previa",
    cannot_open: "No se puede abrir el documento:",
    page_of: "Página {p} de {n}",
    preview_unavailable: "Vista previa no disponible",
    no_pdfium: "Sin vista previa (falta la biblioteca pdfium)",
    default_pos: "posición predeterminada",
    stamp_on_page: "El sello está en la página {n}",
    log_heading: "Registro",
    drop_overlay: "Suelta aquí los archivos PDF",
    sample_name: "Nombre Apellido",
    stamp_signed_by: "Firmado digitalmente por",
    stamp_date: "Fecha",
    err_store: "No se puede abrir el almacén de certificados personales",
    err_cert_not_found: "No se encontró el certificado en el almacén",
    err_key_alg: "Algoritmo de clave no admitido",
    err_no_key: "Sin acceso a la clave privada del certificado",
    err_not_cng: "La clave no es una clave CNG",
    err_sign_refused: "Se rechazó la firma con la clave",
    err_invalid_pdf: "PDF no válido",
    err_invalid_cert: "Archivo de certificado no válido (no contiene un certificado)",
    err_encrypted: "No se admiten archivos PDF cifrados (protegidos con contraseña)",
    err_no_pages: "El PDF no tiene páginas",
    err_pdf_structure: "Estructura de PDF dañada",
    err_too_large: "El archivo es demasiado grande",
    err_sig_too_big: "La firma no cabe en el espacio reservado",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_langid_maps_to_supported_or_english() {
        assert_eq!(Lang::from_langid(0x0402), Lang::Bg);
        assert_eq!(Lang::from_langid(0x0407), Lang::De);
        assert_eq!(Lang::from_langid(0x0c07), Lang::De); // de-AT
        assert_eq!(Lang::from_langid(0x0c0a), Lang::Es);
        assert_eq!(Lang::from_langid(0x080a), Lang::Es); // es-MX
        assert_eq!(Lang::from_langid(0x0409), Lang::En);
        assert_eq!(Lang::from_langid(0x040c), Lang::En); // fr-FR falls back
        assert_eq!(Lang::from_langid(0x0419), Lang::En); // ru-RU falls back
    }

    #[test]
    fn placeholders_exist_in_every_translation() {
        for l in Lang::ALL {
            let t = tr(l);
            for (s, ph) in [
                (t.signing_log, "{n}"),
                (t.signing_log, "{cert}"),
                (t.pages, "{n}"),
                (t.already_signed, "{n}"),
                (t.sign_btn, "{n}"),
                (t.page_of, "{p}"),
                (t.page_of, "{n}"),
                (t.stamp_on_page, "{n}"),
            ] {
                assert!(s.contains(ph), "{l:?}: '{s}' is missing {ph}");
            }
        }
    }
}
