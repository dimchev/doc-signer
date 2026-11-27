"""Generates XAdES fixtures signed by signxml (an independent implementation) for the verifier tests."""
import datetime, pathlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree
from signxml import CanonicalizationMethod, SignatureMethod
from signxml.xades import XAdESSigner

out = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "xades"
out.mkdir(parents=True, exist_ok=True)
doc = '<Invoice xmlns="urn:example:invoice" xmlns:cbc="urn:example:basic"><cbc:ID>42</cbc:ID><cbc:Note xml:lang="bg">Тест</cbc:Note></Invoice>'

def cert_for(key, name):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(4242).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))

cases = {
    "signxml-rsa-c14n11.xml": (rsa.generate_private_key(public_exponent=65537, key_size=2048), SignatureMethod.RSA_SHA256, CanonicalizationMethod.CANONICAL_XML_1_1),
    "signxml-ecdsa-exc.xml": (ec.generate_private_key(ec.SECP256R1()), SignatureMethod.ECDSA_SHA256, CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0),
}
for name, (key, alg, c14n) in cases.items():
    cert = cert_for(key, "signxml fixture " + name)
    signed = XAdESSigner(signature_algorithm=alg, c14n_algorithm=c14n).sign(etree.fromstring(doc.encode()), key=key, cert=[cert.public_bytes(Encoding.PEM).decode()])
    (out / name).write_bytes(etree.tostring(signed, xml_declaration=True, encoding="UTF-8"))
    print(name)
