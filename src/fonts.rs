//! System font lookup shared by the UI and the signature stamp.
//!
//! Windows: `%WINDIR%\Fonts`. Linux/Unix: the usual font folders are indexed recursively once,
//! so distribution-specific layouts (`truetype/dejavu/` on Debian, `dejavu/` on Arch,
//! `dejavu-sans-fonts/` on Fedora, …) all work.

use std::path::PathBuf;

/// Font file names in order of preference.
pub struct Family {
    pub regular: &'static [&'static str],
    pub mono: &'static [&'static str],
    pub symbols: &'static [&'static str],
}

#[cfg(windows)]
pub const SYSTEM: Family = Family {
    regular: &["segoeui.ttf", "arial.ttf", "tahoma.ttf"],
    mono: &["consola.ttf", "cour.ttf"],
    symbols: &["seguisym.ttf", "seguiemj.ttf"],
};

#[cfg(not(windows))]
pub const SYSTEM: Family = Family {
    regular: &["DejaVuSans.ttf", "NotoSans-Regular.ttf", "LiberationSans-Regular.ttf"],
    mono: &["DejaVuSansMono.ttf", "NotoSansMono-Regular.ttf", "LiberationMono-Regular.ttf"],
    symbols: &[],
};

/// Stamp font files (regular, bold) per family, in order of preference.
/// On Windows Arial keeps the established stamp look for the sans family.
pub fn stamp_files(family: crate::style::FontFamily) -> (&'static [&'static str], &'static [&'static str]) {
    use crate::style::FontFamily::*;
    #[cfg(windows)]
    match family {
        Sans => (&["arial.ttf", "segoeui.ttf", "tahoma.ttf"], &["arialbd.ttf", "segoeuib.ttf"]),
        Serif => (&["times.ttf", "georgia.ttf", "cambria.ttc"], &["timesbd.ttf", "georgiab.ttf", "cambriab.ttf"]),
        Mono => (&["consola.ttf", "cour.ttf"], &["consolab.ttf", "courbd.ttf"]),
    }
    #[cfg(not(windows))]
    match family {
        Sans => (SYSTEM.regular, &["DejaVuSans-Bold.ttf", "NotoSans-Bold.ttf", "LiberationSans-Bold.ttf"]),
        Serif => (
            &["DejaVuSerif.ttf", "NotoSerif-Regular.ttf", "LiberationSerif-Regular.ttf"],
            &["DejaVuSerif-Bold.ttf", "NotoSerif-Bold.ttf", "LiberationSerif-Bold.ttf"],
        ),
        Mono => (SYSTEM.mono, &["DejaVuSansMono-Bold.ttf", "NotoSansMono-Bold.ttf", "LiberationMono-Bold.ttf"]),
    }
}
/// Bytes of the first font in `names` that exists on this system.
pub fn find(names: &[&str]) -> Option<Vec<u8>> {
    names.iter().find_map(|n| path_of(n)).and_then(|p| std::fs::read(p).ok())
}

#[cfg(windows)]
fn path_of(name: &str) -> Option<PathBuf> {
    let dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let p = PathBuf::from(dir).join("Fonts").join(name);
    p.exists().then_some(p)
}

#[cfg(not(windows))]
fn path_of(name: &str) -> Option<PathBuf> {
    index().get(&name.to_ascii_lowercase()).cloned()
}

#[cfg(not(windows))]
fn roots() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/usr/share/fonts"), PathBuf::from("/usr/local/share/fonts")];
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    if let Some(d) = data_home {
        v.push(d.join("fonts"));
    }
    if let Some(h) = std::env::var_os("HOME") {
        v.push(PathBuf::from(h).join(".fonts"));
    }
    v
}

/// Lower-cased file name -> first path found; built once.
#[cfg(not(windows))]
fn index() -> &'static std::collections::HashMap<String, PathBuf> {
    use std::collections::HashMap;
    static INDEX: std::sync::OnceLock<HashMap<String, PathBuf>> = std::sync::OnceLock::new();
    INDEX.get_or_init(|| {
        let mut map = HashMap::new();
        for root in roots() {
            scan(&root, 0, &mut map);
        }
        map
    })
}

#[cfg(not(windows))]
fn scan(dir: &std::path::Path, depth: usize, map: &mut std::collections::HashMap<String, PathBuf>) {
    const MAX_DEPTH: usize = 6;
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if depth < MAX_DEPTH {
                scan(&p, depth + 1, map);
            }
        } else if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
            map.entry(n.to_ascii_lowercase()).or_insert(p);
        }
    }
}

/// The proportional font bundled with egui (Ubuntu Light, covers Latin and Cyrillic).
/// Always available, so the stamp is never rendered without text.
pub fn builtin() -> Vec<u8> {
    let defs = eframe::egui::FontDefinitions::default();
    defs.font_data
        .get("Ubuntu-Light")
        .map(|d| (*d.font).as_ref().to_vec())
        .expect("egui default fonts are enabled")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_font_is_available_and_parses() {
        assert!(ab_glyph::FontVec::try_from_vec(builtin()).is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn index_finds_fonts_in_nested_folders() {
        let root = std::env::temp_dir().join(format!("doc-signer-fonts-{}", std::process::id()));
        let nested = root.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("Example-Regular.TTF"), b"x").unwrap();
        let mut map = std::collections::HashMap::new();
        scan(&root, 0, &mut map);
        assert_eq!(map.get("example-regular.ttf"), Some(&nested.join("Example-Regular.TTF")));
        let _ = std::fs::remove_dir_all(&root);
    }
}
