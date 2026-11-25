# Doc Signer

A small desktop application (Rust + egui) for digitally signing PDF documents — without Adobe. Runs on **Windows** and **Linux**.

## Downloads

Prebuilt binaries (built from `master` by GitHub Actions) are on the [Releases page](https://github.com/dimchev/doc-signer/releases):

- **Windows x64** — `doc-signer-windows-x64.zip`: unzip and run `doc-signer.exe` (`pdfium.dll` is included for the page preview).
- **Linux x64** — `doc-signer-linux-x64.tar.gz`: extract and run `./doc-signer`. Needs the GTK3 and X11 system libraries (e.g. `sudo apt install libgtk-3-0 libx11-6`); `libpdfium.so` is included for the page preview.

## Features

- Sign one or many PDF files (button, `Ctrl+O`, drag & drop of files or a folder, or command-line arguments).
- Choose a personal certificate with a private key. Certificates with the document-signing extended key usage are sorted to the top and marked with ★.
- The signature is PAdES (`ETSI.CAdES.detached`, SHA-256) and is added as an *incremental update*, so existing signatures stay valid.
- Optional visible stamp (name, date, reason, location — Cyrillic included). Position it by clicking or dragging on the page preview; by default it is placed at the bottom-right of the last page.
- The result is a new file with a suffix (default ` - signed`) or an overwrite of the original.

## Certificates

### Windows

Certificates are read from the personal store (`CurrentUser\My`). The private key is used through Windows CNG — for smart cards, Windows itself shows the PIN prompt. Only CNG keys are supported (CSP-only keys are not).

### Linux

Certificates are read as files from the first folder that exists:

1. `$DOC_SIGNER_CERTS_DIR`
2. `$XDG_CONFIG_HOME/DocSigner/certs`
3. `~/.config/DocSigner/certs`

Supported file formats:

- **PKCS#12** (`.p12`, `.pfx`) — certificate + key (+ optional chain) in one file. The passphrase is taken from the `DOC_SIGNER_PASS` environment variable, or from a `.pass` file next to the PKCS#12 file (first line).
- **X.509 + private key** — a `.crt`, `.cer`, `.der` or `.pem` certificate plus the matching private key in a file next to it (e.g. `signer.crt` + `signer.key`, or `signer.pem` + `signer.key.pem`).

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

## Limitations

- Encrypted (password-protected) PDFs are not supported.
- No time stamp (TSA) and no LTV data; the signature is at PAdES **B-B** level.
- RSA and ECDSA keys are supported (on Windows only CNG keys, see above).

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

