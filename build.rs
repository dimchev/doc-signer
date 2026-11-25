// Copies the pdfium library (optional, used for page previews) next to the built executable:
// pdfium.dll on Windows, libpdfium.so on Linux.
use std::path::PathBuf;

fn main() {
    let srcs = ["pdfium/bin/pdfium.dll", "pdfium/bin/libpdfium.so"];
    for src in &srcs {
        let src = PathBuf::from(src);
        println!("cargo:rerun-if-changed={}", src.display());
        if !src.exists() {
            continue;
        }
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        // OUT_DIR lives under target/<profile>/build/...; the profile dir is the parent of "build".
        if let Some(profile_dir) = out_dir
            .ancestors()
            .find(|p| p.file_name().is_some_and(|n| n == "build"))
            .and_then(|b| b.parent())
        {
            let _ = std::fs::copy(&src, profile_dir.join(src.file_name().unwrap()));
        }
    }
}
