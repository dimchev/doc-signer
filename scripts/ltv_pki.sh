#!/usr/bin/env bash
# Test PKI for long-term validation (PAdES B-LT) tests.
#
#   scripts/ltv_pki.sh <out-dir>
#
# Creates a root CA, an OCSP responder certificate (id-pkix-ocsp-nocheck) and a document-signing
# leaf whose AIA / CRL DP point to 127.0.0.1 (the URLs contain a space on purpose, like real
# AD CS certificates):
#   caIssuers  http://127.0.0.1:8080/root ca.crt
#   CRL        http://127.0.0.1:8080/root ca.crl
#   OCSP       http://127.0.0.1:8081/ocsp
# plus leaf.p12 (password "test", with the chain), root.crl, the OCSP request for the leaf and
# a "good" and a "revoked" OCSP response. The unit-test fixtures in tests/fixtures/ltv were made
# with this script; CI runs it again and serves the URLs (python http.server + openssl ocsp).
set -euo pipefail
out=${1:?usage: ltv_pki.sh <out-dir>}
mkdir -p "$out"
cd "$out"
export MSYS_NO_PATHCONV=1

cat > ca.cnf <<'EOF'
[ca]
default_ca = test_ca
[test_ca]
dir = .
database = index.txt
new_certs_dir = .
serial = serial.txt
crlnumber = crlnumber.txt
default_md = sha256
default_days = 3650
default_crl_days = 3650
policy = any
unique_subject = no
[any]
commonName = supplied
[req]
distinguished_name = dn
prompt = no
[dn]
CN = unused
[root]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ocsp]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
noCheck = ignored
[leaf]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = 1.3.6.1.4.1.311.10.3.12, emailProtection
authorityKeyIdentifier = keyid
authorityInfoAccess = OCSP;URI:http://127.0.0.1:8081/ocsp, caIssuers;URI:http://127.0.0.1:8080/root ca.crt
crlDistributionPoints = URI:http://127.0.0.1:8080/root ca.crl
EOF
: > index.txt
echo 1000 > serial.txt
echo 01 > crlnumber.txt

openssl req -x509 -new -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
  -subj "/CN=Doc Signer Test Root CA/O=Doc Signer Tests" -config ca.cnf -extensions root
for name in ocsp leaf; do
  cn="Doc Signer Test OCSP"; [ "$name" = leaf ] && cn="Doc Signer LTV Signer"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$cn" -config ca.cnf
  openssl ca -batch -config ca.cnf -cert root.pem -keyfile root.key -in "$name.csr" -out "$name.pem" -extensions "$name" -notext
done
openssl ca -batch -config ca.cnf -cert root.pem -keyfile root.key -gencrl -out root.crl.pem
openssl crl -in root.crl.pem -outform DER -out root.crl
cp root.pem "root ca.crt"
cp root.crl "root ca.crl"
openssl pkcs12 -export -in leaf.pem -inkey leaf.key -certfile root.pem -passout pass:test -out leaf.p12

openssl ocsp -issuer root.pem -cert leaf.pem -no_nonce -reqout ocsp-request.der
openssl ocsp -index index.txt -CA root.pem -rsigner ocsp.pem -rkey ocsp.key -reqin ocsp-request.der -respout ocsp-good.der -ndays 3650
cp index.txt index-revoked.txt
serial=$(openssl x509 -in leaf.pem -noout -serial | cut -d= -f2)
sed -i "s/^V\(\t[^\t]*\t\)\t$serial/R\1$(date -u +%y%m%d%H%M%SZ)\t$serial/" index-revoked.txt
openssl ocsp -index index-revoked.txt -CA root.pem -rsigner ocsp.pem -rkey ocsp.key -reqin ocsp-request.der -respout ocsp-revoked.der -ndays 3650
openssl ocsp -respin ocsp-revoked.der -resp_text -noverify | grep -q "Cert Status: revoked"
echo "test PKI ready in $PWD"
