# Doc Signer

A small desktop application (Rust + egui) for digitally signing PDF documents - without Adobe. Runs on **Windows** and **Linux**.

## Downloads

Prebuilt binaries (built from `master` by GitHub Actions) are on the [Releases page](https://github.com/dimchev/doc-signer/releases):

- **Windows x64** - `doc-signer-windows-x64.zip`: unzip and run `doc-signer.exe` (`pdfium.dll` is included for the page preview).
- **Linux x64** - `doc-signer-linux-x64.tar.gz`: extract and run `./doc-signer` (`libpdfium.so` is included for the page preview). Built on Ubuntu 22.04, so it needs **glibc ≥ 2.35**, **OpenSSL 3** (`libssl3`), **GTK 3** and **X11** - e.g. Ubuntu 22.04+, Debian 12+, Fedora 36+, current Arch (`sudo apt install libgtk-3-0 libx11-6 libssl3`). On older distributions, build from source.

## Features

- Sign one or many PDF files (button, `Ctrl+O`, drag & drop of files or a folder, or command-line arguments).
- **Any other file** (docx, xlsx, odt, images, zip, …) is signed as a whole with a CAdES signature: **`.p7s`** (separate signature file, the original stays unchanged) or **`.p7m`** (the file embedded in the signature). Verify e.g. with `openssl cms -verify -binary -inform DER -in file.docx.p7s -content file.docx -CAfile <root>` or the EU DSS validator.
- **ASiC-E container** (`.asice`, ETSI EN 319 162-1): choose *.asice* under Output to pack all checked non-PDF files into one ZIP with `META-INF/ASiCManifest.xml` (SHA-256 of every file) and one CAdES signature over it (`META-INF/signature001.p7s`). The container is named after the first file. Open it with any ZIP tool, or validate it with the EU DSS validator.
- Choose a personal certificate with a private key. Certificates with the document-signing extended key usage are sorted to the top and marked with ★.
- The signature is PAdES (`ETSI.CAdES.detached`, SHA-256) and is added as an *incremental update*, so existing signatures stay valid.
- **Password-protected PDFs** (RC4 40/128-bit, AES-128, AES-256): files with only an owner password open directly; for a file with an open password click *🔑 Enter password…* on its card. The signed file keeps the same encryption and passwords. If the document's permissions forbid signing (no "fill in forms" / "annotate"), the owner password is needed. Passwords are kept in memory only.
- Optional visible stamp (name, date, reason, location - Cyrillic included). Position it by clicking or dragging on the page preview and **resize it by dragging a corner** (Shift keeps the proportions); by default it is placed at the bottom-right of the last page. Each document can use its own style (🎨 on the document card).
- **Stamp styles**: pick a style in the gallery (Classic, Minimal, Badge, Corporate, Handwritten, Round seal) or create your own with *Edit…* - shape (rectangle, rounded, ellipse, **round seal** with text along the arcs, no border), colours, border (single/double/dashed), font, an **image** (handwritten signature, logo or company seal - from PNG / JPG / SVG / PDF, drawn in the app, or **taken from a signature in an already signed PDF** (e.g. made with Adobe, B-Trust, Evrotrust or pyHanko - needs pdfium); white backgrounds of scans are removed automatically; placed left, right, on top or behind the text), and which fields are shown in which order (with `{name}`, `{date}`, `{reason}`, `{location}`, `{issuer}`, `{contact}` placeholders). The "Digitally signed by" label and the signer's name are always shown. Styles are stored in `%APPDATA%\DocSigner\styles` (Linux: `~/.config/DocSigner/styles`) and can be shared with *⋯ → Export / Import* (`.json`); a style saved as *locked* can only be duplicated. See [docs/design/stamp-appearance.md](docs/design/stamp-appearance.md).
- Optional **trusted timestamp** (RFC 3161, PAdES B-T): the signing time comes from a time-stamp authority (default `http://timestamp.digicert.com`, configurable) instead of the PC clock. Only a hash of the signature is sent. If the TSA cannot be reached, signing fails rather than silently producing a signature without the timestamp.
- Optional **long-term validation** (with the timestamp): *Long-term validation (PAdES B-LT)* downloads the revocation status (OCSP, or the CRL) of the signer's and the TSA's certificates, completes missing chain certificates from the AIA addresses, and stores everything in the PDF's document security store (`/DSS`), so the signature can still be verified after the certificates expire or the CA is gone. *Archive timestamp (PAdES B-LTA)* then adds a document timestamp over the whole file. If the data cannot be fetched (offline, LDAP-only addresses), the signature stays B-T and the log shows a warning. SHA-1 signed OCSP responses (not accepted by current validators) are replaced by the CRL when one is available.
- **Verify signatures** (🔍 *Verify* on a card or next to a signed result): for signed PDFs (all signatures and document timestamps, also from other tools), `.p7s` (the original must be next to it), `.p7m` and ASiC containers (`.asice` / `.asics`). Shows the signer, the PAdES / CAdES level and checks: the signed content is unchanged, the signature value, the RFC 3161 timestamp, the certificate chain against the computer's trusted roots at the signing time, and what was added to a PDF after each signature (later signatures and validation data are fine, other changes are flagged).
- The result is a new file with a suffix (default ` - signed`) or an overwrite of the original.

## Certificates

### Windows

Certificates are read from the personal store (`CurrentUser\My`). The private key is used through Windows CNG, or the legacy CryptoAPI (CSP) for older smart-card middleware (RSA with a provider that supports SHA-256) - for smart cards, Windows itself shows the PIN prompt.

### Linux

Certificates are read as files from the first folder that exists:

1. `$DOC_SIGNER_CERTS_DIR`
2. `$XDG_CONFIG_HOME/DocSigner/certs`
3. `~/.config/DocSigner/certs`

Supported file formats:

- **PKCS#12** (`.p12`, `.pfx`) - certificate + key (+ optional chain) in one file. The passphrase is taken from the `DOC_SIGNER_PASS` environment variable, or from a `.pass` file next to the PKCS#12 file (first line).
- **X.509 + private key** - a `.crt`, `.cer`, `.der` or `.pem` certificate plus the matching private key in a file next to it (e.g. `signer.crt` + `signer.key`, or `signer.pem` + `signer.key.pem`).

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

Set `DOC_SIGNER_LTV=1` (B-LT) or `DOC_SIGNER_LTA=1` (B-LTA, needs `DOC_SIGNER_TSA`) to add long-term validation data, and validate with `--expect-lt` / `--expect-lta` (offline, using only the data in the PDF). `scripts/ltv_pki.sh` creates the test PKI used in CI (CA, CRL and OCSP responder on 127.0.0.1). For an encrypted PDF set `DOC_SIGNER_PDF_PASSWORD` for the test and add `--password <pw>` to the validator. The fixtures in `tests/fixtures/encrypted` are generated by `scripts/make_encrypted_fixtures.py` (pikepdf).

CI does this on Linux (OpenSSL key from a file) and on Windows (a throwaway CNG key in `CurrentUser\My`), using the fixture `tests/fixtures/minimal.pdf`.

## Limitations

- Encrypted PDFs with a certificate (public-key) security handler are not supported, only the standard password handler.
- Without a time stamp the signature is PAdES **B-B**; with *Add trusted timestamp (TSA)* it is **B-T**, plus **B-LT** / **B-LTA** with the long-term options.
- *Verify* does not check revocation (OCSP / CRL) and does not support XAdES (`signatures.xml`) or RSASSA-PSS signatures.
- Revocation data is fetched over HTTP(S) only (no LDAP). The validation data is added for the new signature, not refreshed for older signatures in the document.
- RSA and ECDSA keys are supported (ECDSA on Windows only as CNG keys; legacy CSP keys are RSA-only).
- ASiC-E containers are created, not opened or extended; a container is limited to 4 GB (no ZIP64). PDFs are always signed as PAdES and not packed into the container.

## Third-party

- [pdfium](https://github.com/bblanchon/pdfium) (Apache License 2.0) - optional, for page preview.
- [lopdf](https://github.com/lopdf/lopdf) - PDF parsing.
- [egui / eframe](https://github.com/emilk/egui) - GUI.
- [openssl](https://github.com/rust-openssl/openssl) (Linux) - certificate and key handling.

## License

Licensed under either of

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

