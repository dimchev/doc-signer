# Doc Signer

A small desktop application (Rust + egui) for digitally signing PDF documents — without Adobe. Runs on **Windows** and **Linux**.

## Downloads

Prebuilt binaries (built from `master` by GitHub Actions) are on the [Releases page](https://github.com/dimchev/doc-signer/releases):

- **Windows x64** — `doc-signer-windows-x64.zip`: unzip and run `doc-signer.exe` (`pdfium.dll` is included for the page preview).
- **Linux x64** — `doc-signer-linux-x64.tar.gz`: extract and run `./doc-signer` (`libpdfium.so` is included for the page preview). Built on Ubuntu 22.04, so it needs **glibc ≥ 2.35**, **OpenSSL 3** (`libssl3`), **GTK 3** and **X11** — e.g. Ubuntu 22.04+, Debian 12+, Fedora 36+, current Arch (`sudo apt install libgtk-3-0 libx11-6 libssl3`). On older distributions, build from source.

## Features

- Sign one or many PDF files (button, `Ctrl+O`, drag & drop of files or a folder, or command-line arguments).
- Choose a personal certificate with a private key. Certificates with the document-signing extended key usage are sorted to the top and marked with ★.
- The signature is PAdES (`ETSI.CAdES.detached`, SHA-256) and is added as an *incremental update*, so existing signatures stay valid.
- Optional visible stamp (name, date, reason, location — Cyrillic included). Position it by clicking or dragging on the page preview and **resize it by dragging a corner** (Shift keeps the proportions); by default it is placed at the bottom-right of the last page. Each document can use its own style (🎨 on the document card).
- **Stamp styles**: pick a style in the gallery (Classic, Minimal, Badge, Corporate, Handwritten, Round seal) or create your own with *Edit…* — shape (rectangle, rounded, ellipse, **round seal** with text along the arcs, no border), colours, border (single/double/dashed), font, an **image** (handwritten signature, logo or company seal — from PNG / JPG / SVG / PDF, drawn in the app, or **taken from a signature in an already signed PDF** (e.g. made with Adobe, B-Trust, Evrotrust or pyHanko — needs pdfium); white backgrounds of scans are removed automatically; placed left, right, on top or behind the text), and which fields are shown in which order (with `{name}`, `{date}`, `{reason}`, `{location}`, `{issuer}`, `{contact}` placeholders). The "Digitally signed by" label and the signer's name are always shown. Styles are stored in `%APPDATA%\DocSigner\styles` (Linux: `~/.config/DocSigner/styles`) and can be shared with *⋯ → Export / Import* (`.json`); a style saved as *locked* can only be duplicated. See [docs/design/stamp-appearance.md](docs/design/stamp-appearance.md).
- The result is a new file with a suffix (default ` - signed`) or an overwrite of the original.

## Certificates

### Windows

Certificates are read from the personal store (`CurrentUser\My`). The private key is used through Windows CNG, or the legacy CryptoAPI (CSP) for older smart-card middleware (RSA with a provider that supports SHA-256) — for smart cards, Windows itself shows the PIN prompt.

### Linux

Certificates are read as files from the first folder that exists:

1. `$DOC_SIGNER_CERTS_DIR`
2. `$XDG_CONFIG_HOME/DocSigner/certs`
3. `~/.config/DocSigner/certs`

Supported file formats:

- **PKCS#12** (`.p12`, `.pfx`) — certificate + key (+ optional chain) in one file. The passphrase is taken from the `DOC_SIGNER_PASS` environment variable, or from a `.pass` file next to the PKCS#12 file (first line).
- **X.509 + private key** — a `.crt`, `.cer`, `.der` or `.pem` certificate plus the matching private key in a file next to it (e.g. `signer.crt` + `signer.key`, or `signer.pem` + `signer.key.pem`).

Passphrases:

- `DOC_SIGNER_PASS` applies to **every** key and PKCS#12 file in the folder.
- A `.pass` file (e.g. `signer.p12.pass`, `signer.key.pass`) stores the passphrase in plain text. It must be readable only by you (`chmod 600 signer.p12.pass`); like ssh, the app ignores it when group or others can read it.
- Files that cannot be parsed are skipped; the certificate list is re-read with the ⟳ button.

## Building

### Windows

```powershell
cargo build --release
```

The executable is `target\release\doc-signer.exe`.

### Linux

Install the system dependencies (Debian/Ubuntu names; adjust for your distribution):

```sh
sudo apt install pkg-config libssl-dev libgtk-3-dev libx11-dev
```

Then:

```sh
cargo build --release
```

The executable is `target/release/doc-signer`.

### Page preview (optional)

Page rendering uses [pdfium](https://github.com/bblanchon/pdfium-binaries):

- **Windows:** extract `pdfium-win-x64.tgz` into `pdfium\` in the project root. `build.rs` copies `pdfium\bin\pdfium.dll` next to the executable at build time.
- **Linux:** place `libpdfium.so` into `pdfium/bin/`. `build.rs` copies it next to the executable.

Without the pdfium library the app still works; pages are simply shown blank.

## Tests

```sh
cargo test
```

End-to-end test with a real certificate (skipped automatically when the variables are not set):

```sh
export DOC_SIGNER_TEST_PDF=/path/to/file.pdf
export DOC_SIGNER_THUMB="<SHA-1 fingerprint of the certificate, 40 hex chars>"
cargo test -- --include-ignored
```

The test writes `<file>.pdf.signed.pdf`. To validate it independently (pyhanko: integrity, signature, trust chain and the PAdES signed attributes), run:

```sh
pip install pyhanko pyhanko-certvalidator
python scripts/validate_signature.py /path/to/file.pdf.signed.pdf /path/to/signer-or-root.crt
```

CI does this on Linux (OpenSSL key from a file) and on Windows (a throwaway CNG key in `CurrentUser\My`), using the fixture `tests/fixtures/minimal.pdf`.

## Limitations

- Encrypted (password-protected) PDFs are not supported.
- No time stamp (TSA) and no LTV data; the signature is at PAdES **B-B** level.
- RSA and ECDSA keys are supported (ECDSA on Windows only as CNG keys; legacy CSP keys are RSA-only).

## Third-party

- [pdfium](https://github.com/bblanchon/pdfium) (Apache License 2.0) — optional, for page preview.
- [lopdf](https://github.com/lopdf/lopdf) — PDF parsing.
- [egui / eframe](https://github.com/emilk/egui) — GUI.
- [openssl](https://github.com/rust-openssl/openssl) (Linux) — certificate and key handling.

## License

Licensed under either of

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

