"""Independent validation of XAdES signatures made by doc-signer (used by CI), with signxml.

Usage: python scripts/validate_xades.py <signed.xml> <trust-root.(pem|der|cer|crt)>

Enveloped signatures only: checks the document reference, the SignedProperties reference,
the signature value and the certificate chain to the trust root.
"""

import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from signxml import SignatureConfiguration
from signxml.xades import XAdESVerifier


def main(xml_path: str, root_path: str) -> int:
    raw = open(root_path, "rb").read()
    cert = x509.load_pem_x509_certificate(raw) if raw.startswith(b"-----") else x509.load_der_x509_certificate(raw)
    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as pem:
        pem.write(cert.public_bytes(Encoding.PEM))
    data = open(xml_path, "rb").read()
    results = XAdESVerifier().verify(data, ca_pem_file=pem.name, expect_config=SignatureConfiguration(require_x509=True), expect_references=2)
    for r in results:
        print("reference OK:", r.signed_xml.tag if r.signed_xml is not None else "(external)")
    print("OK: XAdES signature validated by signxml")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
