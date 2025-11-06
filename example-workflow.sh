#!/bin/bash
# Example script demonstrating the full AMHS PKI workflow

set -e

echo "========================================="
echo "AMHS PKI Demonstration - Full Workflow"
echo "========================================="
echo ""

# Check if root CA exists
if [ ! -f "root-demo.crt" ] || [ ! -f "root-demo.key" ]; then
    echo "Step 1: Generating Root CA..."
    bash ./generate-root-ca.sh
    echo ""
else
    echo "Step 1: Root CA already exists (skipping)"
    echo ""
fi

# Build the tool
echo "Step 2: Building AMHS PKI tool..."
go build -o amhs-pki-demo .
echo "✓ Build successful"
echo ""

# Generate AMHS Issuing CA
echo "Step 3: Generating AMHS Issuing CA..."
./amhs-pki-demo generate -type ca -output amhs-ca -validity 5475
echo ""

# Validate CA
echo "Step 4: Validating CA certificate..."
./amhs-pki-demo validate -cert amhs-ca.crt -type ca
echo ""

# Generate MTA certificates for different airports
echo "Step 5: Generating MTA certificates..."
echo ""

echo "5a. Generating MTA for Frankfurt, Germany ()..."
./amhs-pki-demo generate \
    -type mta \
    -output mta-de-fra1 \
    -subject "MTA-EDDD-1" \
    -validity 730 \
    -mta-name "MTA-EDDD-1"
echo ""

# Validate MTA certificates
echo "Step 6: Validating MTA certificate..."
echo ""

for mta in de-fra1; do
    echo "Validating mta-${mta}.crt..."
    ./amhs-pki-demo validate -cert mta-${mta}.crt -type mta
    echo ""
done

# Generate signing certificates
echo "Step 7: Generating Signing certificates..."
echo ""

echo "7a. Generating UA signing certificate..."
./amhs-pki-demo generate \
    -type signing \
    -output ua-paris \
    -subject "UA-LFPGZTZX" \
    -validity 730
echo ""

echo "7b. Generating MTCU signing certificate..."
./amhs-pki-demo generate \
    -type signing \
    -output mtcu-london \
    -subject "MTCU-EGLLZTZX" \
    -validity 730
echo ""

# Validate signing certificates
echo "Step 8: Validating Signing certificates..."
echo ""

for cert in ua-paris mtcu-london; do
    echo "Validating ${cert}.crt..."
    ./amhs-pki-demo validate -cert ${cert}.crt -type signing
    echo ""
done

# Display certificate information
echo "Step 9: Displaying certificate information..."
echo ""

echo "=== AMHS Issuing CA Certificate ==="
./amhs-pki-demo info amhs-ca.crt
echo ""

echo "=== Signing Certificate (UA Paris) ==="
./amhs-pki-demo info ua-paris.crt
echo ""

# Summary
echo "========================================="
echo "Workflow Complete!"
echo "========================================="
echo ""
echo "Generated certificates:"
echo "  - Root CA: root-demo.crt"
echo "  - Issuing CA: amhs-ca.crt"
echo "  - MTA Certificates: mta-de-fra1.crt"
echo "  - Signing Certificates: ua-paris.crt, mtcu-london.crt"
echo ""
echo "All certificates validated successfully!"
echo ""
echo "You can now:"
echo "  - Test interoperability with AMHS implementations"
echo "  - Experiment with different certificate attributes"
echo "  - Validate custom certificates against profiles"
echo ""
