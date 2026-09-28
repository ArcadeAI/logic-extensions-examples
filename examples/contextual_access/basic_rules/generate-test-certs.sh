#!/bin/bash
# Generate test certificates for mTLS testing
#
# This script creates:
# - CA certificate (ca.crt, ca.key) - Used to sign both server and client certs
# - Server certificate (server.crt, server.key) - Used by the webhook test server
# - Client certificate (client.crt, client.key) - Used by the Arcade Engine
#
# Usage: ./generate-test-certs.sh [output_dir]

set -e

OUTPUT_DIR="${1:-.}"
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "🔐 Generating test certificates for mTLS..."
echo "   Output directory: $(pwd)"
echo ""

# Generate CA private key and certificate
echo "1. Generating CA certificate..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=US/ST=Test/L=Test/O=Arcade Test CA/CN=Arcade Test CA"

# Generate server private key and CSR
echo "2. Generating server certificate..."
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=Test/L=Test/O=Arcade Test/CN=localhost"

# Create server certificate extensions file for SAN
cat > server_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign server certificate with CA
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -extfile server_ext.cnf

# Generate client private key and CSR
echo "3. Generating client certificate..."
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=Test/L=Test/O=Arcade Engine/CN=arcade-engine-client"

# Create client certificate extensions file
cat > client_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Sign client certificate with CA
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -extfile client_ext.cnf

# Clean up CSR and extension files
rm -f server.csr client.csr server_ext.cnf client_ext.cnf ca.srl

echo ""
echo "✅ Certificates generated successfully!"
echo ""
echo "Files created:"
echo "  ca.crt      - CA certificate (use with -ca flag on server, and as ca_cert in plugin config)"
echo "  ca.key      - CA private key (keep secure)"
echo "  server.crt  - Server certificate (use with -cert flag)"
echo "  server.key  - Server private key (use with -key flag)"
echo "  client.crt  - Client certificate (use as client_cert in plugin config)"
echo "  client.key  - Client private key (use as client_key in plugin config)"
echo ""
echo "To start the mTLS test server:"
echo "  go run ./examples/contextual_access/basic_rules -port 8888 -tls -cert server.crt -key server.key -ca ca.crt"
echo ""
echo "To test with curl:"
echo "  curl --cacert ca.crt --cert client.crt --key client.key https://localhost:8888/health"
echo ""
