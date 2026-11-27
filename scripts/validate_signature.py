"""Independent validation of PDFs signed by doc-signer (used by CI).

Usage: python scripts/validate_signature.py <signed.pdf> <trust-root.(pem|der|cer|crt)> [--expect-timestamp] [--expect-lt | --expect-lta] [--password <pw>]

Fails (exit code 1) unless every signature is intact, cryptographically valid,
chains to the given trust root and carries the signed attributes PAdES B-B needs.
The last signature must also cover the entire file. With --expect-timestamp every signature
must carry an intact, valid RFC 3161 signature time-stamp (PAdES B-T).
Encrypted PDFs are decrypted with --password (default: the empty user password).
With --expect-lt the last signature (and its time-stamp) must validate offline with only the
revocation data embedded in the document (DSS). With --expect-lta it must pass the ETSI
EN 319 102-1 long-term validation (pyhanko AdES, no online fetching), which needs the document
time-stamp. The trust root and the system's trusted roots (for the TSA) are accepted.
"""

import asyncio
import inspect
import sys

from pyhanko.sign.diff_analysis import ModificationLevel

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import SignatureCoverageLevel, ades, validate_pdf_signature
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko.sign.validation.policy_decl import (PdfSignatureValidationSpec, RevinfoOnlineFetchingRule,
                                                 RevocationInfoGatheringSpec, SignatureValidationSpec)
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule
from pyhanko_certvalidator.registry import SimpleTrustManager
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


def check_long_term(reader, sig, root, level: str) -> list:
    """Offline validation that relies on the validation data in the document (DSS) only."""
    rule = RevocationCheckingRule.CRL_OR_OCSP_REQUIRED
    revinfo = CertRevTrustPolicy(RevocationCheckingPolicy(ee_certificate_rule=rule, intermediate_ca_cert_rule=rule))
    if "/DSS" not in reader.root:
        return ["no document security store (/DSS): the PDF has no long-term validation data"]
    if level == "lt":
        dss = DocumentSecurityStore.read_dss(reader)
        vc = dss.as_validation_context({"extra_trust_roots": [root], "allow_fetching": False, "revinfo_policy": revinfo})
        status = validate_pdf_signature(sig, signer_validation_context=vc, ts_validation_context=vc)
        ok = status.intact and status.valid and status.trusted and status.timestamp_validity is not None and status.timestamp_validity.trusted
        print(f"B-LT (embedded revocation data only): {status.summary()}")
        return [] if ok else [f"{sig.field_name}: not valid with the embedded validation data alone"]
    trust = SimpleTrustManager.build(extra_trust_roots=[root])
    policy = CertValidationPolicySpec(trust_manager=trust, revinfo_policy=revinfo)
    spec = PdfSignatureValidationSpec(SignatureValidationSpec(
        cert_validation_policy=policy,
        revinfo_gathering_policy=RevocationInfoGatheringSpec(online_fetching_rule=RevinfoOnlineFetchingRule.LOCAL_ONLY)))
    result = ades.ades_lta_validation(sig, spec)
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    print(f"B-LTA (ETSI EN 319 102-1): {result.ades_subindic}")
    return [] if result.ades_subindic.status.name == "PASSED" else [f"{sig.field_name}: AdES LTA validation: {result.ades_subindic}"]


def main(pdf_path: str, trust_path: str, expect_timestamp: bool = False, password: str = "", ltv: str = "") -> int:
    vc = ValidationContext(trust_roots=[load_cert_from_pemder(trust_path)])
    errors = []
    with open(pdf_path, "rb") as f:
        reader = PdfFileReader(f, strict=False)
        if reader.encrypted:
            reader.decrypt(password)
            print("decrypted:", reader.security_handler.__class__.__name__)
        sigs = reader.embedded_regular_signatures
        if not sigs:
            print("FAIL: no signatures found")
            return 1
        if ltv:
            errors += check_long_term(reader, sigs[-1], load_cert_from_pemder(trust_path), ltv)
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
                # Only DSS / document time-stamp updates may follow a long-term signature.
                if not (ltv and status.modification_level == ModificationLevel.LTA_UPDATES):
                    errors.append(f"{sig.field_name}: last signature does not cover the entire file "
                                  f"(modifications: {status.modification_level})")
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
    flags = {"--expect-timestamp", "--expect-lt", "--expect-lta"}
    args = [a for a in argv if a not in flags]
    if len(args) != 2:
        print(__doc__)
        sys.exit(2)
    ltv = "lta" if "--expect-lta" in argv else "lt" if "--expect-lt" in argv else ""
    sys.exit(main(args[0], args[1], "--expect-timestamp" in argv or bool(ltv), pw, ltv))
