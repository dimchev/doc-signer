"""Independent validation of PDFs signed by doc-signer (used by CI).

Usage: python scripts/validate_signature.py <signed.pdf> <trust-root.(pem|der|cer|crt)> [--expect-timestamp] [--password <pw>]

Fails (exit code 1) unless every signature is intact, cryptographically valid,
chains to the given trust root and carries the signed attributes PAdES B-B needs.
The last signature must also cover the entire file. With --expect-timestamp every signature
must carry an intact, valid RFC 3161 signature time-stamp (PAdES B-T).
Encrypted PDFs are decrypted with --password (default: the empty user password).
"""

import sys

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import SignatureCoverageLevel, validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

try:
    from pyhanko.keys import load_cert_from_pemder
except ImportError:  # older pyhanko
    from pyhanko.sign.general import load_cert_from_pemder

REQUIRED_ATTRS = {
    "1.2.840.113549.1.9.3": "content-type",
    "1.2.840.113549.1.9.4": "message-digest",
    "1.2.840.113549.1.9.16.2.47": "signing-certificate-v2",
}


def main(pdf_path: str, trust_path: str, expect_timestamp: bool = False, password: str = "") -> int:
    vc = ValidationContext(trust_roots=[load_cert_from_pemder(trust_path)])
    errors = []
    with open(pdf_path, "rb") as f:
        reader = PdfFileReader(f, strict=False)
        if reader.encrypted:
            reader.decrypt(password)
            print("decrypted:", reader.security_handler.__class__.__name__)
        sigs = reader.embedded_signatures
        if not sigs:
            print("FAIL: no signatures found")
            return 1
        for i, sig in enumerate(sigs):
            attrs = {a["type"].dotted for a in sig.signer_info["signed_attrs"]}
            status = validate_pdf_signature(sig, signer_validation_context=vc)
            print(f"{sig.field_name}: intact={status.intact} valid={status.valid} "
                  f"trusted={status.trusted} coverage={status.coverage.name}")
            for oid, name in REQUIRED_ATTRS.items():
                if oid not in attrs:
                    errors.append(f"{sig.field_name}: missing signed attribute {name} ({oid})")
            if not (status.intact and status.valid):
                errors.append(f"{sig.field_name}: signature is not intact/valid")
            if not status.trusted:
                errors.append(f"{sig.field_name}: signer does not chain to the trust root")
            if expect_timestamp:
                ts = status.timestamp_validity
                if ts is None:
                    errors.append(f"{sig.field_name}: no signature time-stamp")
                else:
                    print(f"  time-stamp: {ts.timestamp} intact={ts.intact} valid={ts.valid}")
                    if not (ts.intact and ts.valid):
                        errors.append(f"{sig.field_name}: time-stamp is not intact/valid")
            if i == len(sigs) - 1 and status.coverage != SignatureCoverageLevel.ENTIRE_FILE:
                errors.append(f"{sig.field_name}: last signature does not cover the entire file")
    for e in errors:
        print("FAIL:", e)
    if not errors:
        print(f"OK: {len(sigs)} signature(s) validated")
    return 1 if errors else 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    pw = ""
    if "--password" in argv:
        i = argv.index("--password")
        pw = argv[i + 1]
        del argv[i : i + 2]
    args = [a for a in argv if a != "--expect-timestamp"]
    if len(args) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(args[0], args[1], "--expect-timestamp" in argv, pw))
