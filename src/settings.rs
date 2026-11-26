//! Per-user application folder and the `key=value` settings file inside it.
//!
//! Windows: `%APPDATA%\DocSigner`. Linux/Unix: `$XDG_CONFIG_HOME/DocSigner` (default `~/.config/DocSigner`).

use std::path::{Path, PathBuf};

pub fn app_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("DocSigner"))
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME")?;
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from(home).join(".config"));
        Some(base.join("DocSigner"))
    }
}

fn file() -> Option<PathBuf> {
    app_dir().map(|d| d.join("settings.txt"))
}

pub fn get(key: &str) -> Option<String> {
    get_in(&file()?, key)
}

/// Updates one key and keeps every other line of the file.
pub fn set(key: &str, value: &str) {
    if let Some(f) = file() {
        set_in(&f, key, value);
    }
}

fn get_in(path: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let prefix = format!("{key}=");
    text.lines().find_map(|l| l.strip_prefix(&prefix)).map(str::to_string)
}

fn set_in(path: &Path, key: &str, value: &str) {
    let prefix = format!("{key}=");
    let old = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = old.lines().filter(|l| !l.starts_with(&prefix)).map(str::to_string).collect();
    lines.push(format!("{key}={value}"));
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, lines.join("\n") + "\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_keeps_other_keys() {
        let f = std::env::temp_dir().join(format!("doc-signer-settings-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&f);
        set_in(&f, "lang", "bg");
        set_in(&f, "style", "builtin:classic");
        set_in(&f, "lang", "de");
        assert_eq!(get_in(&f, "lang").as_deref(), Some("de"));
        assert_eq!(get_in(&f, "style").as_deref(), Some("builtin:classic"));
        let _ = std::fs::remove_file(&f);
    }
}
