#!/bin/sh
set -e

# OQS-OpenSSL 1.1.1 has PQC algorithms built-in, not as providers.
# This script generates certificates using post-quantum algorithms.

SIG_ALG="dilithium5"
if [ -z "$1" ]; then
    echo "Usage: $0 <certificate_directory>"
    exit 1
fi
CERT_DIR="$1"
DAYS_VALID=365

mkdir -p ${CERT_DIR}

# Verify we're using the custom OpenSSL
echo "Using OpenSSL version:"
/opt/openssl/bin/openssl version
echo ""

echo "Generating PQC certificates using ${SIG_ALG}..."

# 1. Generate CA private key and self-signed certificate
/opt/openssl/bin/openssl req -x509 \
  -newkey ${SIG_ALG} -keyout ${CERT_DIR}/ca.key \
  -out ${CERT_DIR}/ca.crt -nodes -subj "/CN=PQC-CA" -days ${DAYS_VALID}

# 2. Generate server private key and CSR
/opt/openssl/bin/openssl req -new \
  -newkey ${SIG_ALG} -keyout ${CERT_DIR}/server.key \
  -out ${CERT_DIR}/server.csr -nodes -subj "/CN=localhost"

# 3. Sign server certificate with SAN (required by gRPC)
cat <<EOF > ${CERT_DIR}/san.cnf
[req]
distinguished_name=dn
[san]
subjectAltName=DNS:localhost
[dn]
EOF

/opt/openssl/bin/openssl x509 -req \
  -in ${CERT_DIR}/server.csr -out ${CERT_DIR}/server.crt \
  -CA ${CERT_DIR}/ca.crt -CAkey ${CERT_DIR}/ca.key -CAcreateserial \
  -days ${DAYS_VALID} -extfile ${CERT_DIR}/san.cnf -extensions san

# 4. Generate client private key, CSR, and certificate
/opt/openssl/bin/openssl req -new \
  -newkey ${SIG_ALG} -keyout ${CERT_DIR}/client.key \
  -out ${CERT_DIR}/client.csr -nodes -subj "/CN=pqc-client"

/opt/openssl/bin/openssl x509 -req \
  -in ${CERT_DIR}/client.csr -out ${CERT_DIR}/client.crt \
  -CA ${CERT_DIR}/ca.crt -CAkey ${CERT_DIR}/ca.key -CAcreateserial \
  -days ${DAYS_VALID}

# Clean up temporary files
rm ${CERT_DIR}/*.csr ${CERT_DIR}/*.srl ${CERT_DIR}/san.cnf

echo ""
echo "✓ PQC certificates successfully generated using ${SIG_ALG}:"
ls -lh ${CERT_DIR}

# Verify the certificates were created with PQC algorithms
echo ""
echo "Certificate algorithm verification:"
/opt/openssl/bin/openssl x509 -in ${CERT_DIR}/ca.crt -noout -text | grep -A2 "Public Key Algorithm"
