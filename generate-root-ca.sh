#!/bin/bash
# Script to generate a dummy root CA for testing purposes

set -e

echo "Generating dummy Root CA for AMHS PKI Demo..."

# Generate root CA private key (secp384r1)
openssl ecparam -name secp384r1 -genkey -noout -out root-demo.key

# Generate root CA certificate (self-signed, 20 years validity)
openssl req -new -x509 -key root-demo.key -out root-demo.crt -days 7300 \
    -sha384 \
    -subj "/CN=European Aviation Root CA/OU=European Aviation/OU=Common PKI Services/O=EUROCONTROL" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "Root CA generated successfully:"
echo "  Certificate: root-demo.crt"
echo "  Private Key: root-demo.key"
echo ""
echo "Certificate details:"
openssl x509 -in root-demo.crt -text -noout | head -20
