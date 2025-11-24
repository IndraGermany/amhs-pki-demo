# AMHS PKI Demonstration Environment

A Go-based demonstration and playground environment for generating and validating AMHS (Aeronautical Message Handling System) PKI certificates according to Eurocontrol PKI suggestions.

## Overview

This tool implements the AMHS PKI certificate profiles for:
- **CA Certificate**: AMHS Issuing CA (intermediate CA)
- **MTA Certificate**: Message Transfer Agent certificates
- **Signing Certificate**: User Agent and MTCU signing certificates

The implementation follows the specifications with:
- **Signature Algorithm**: SHA-384 with ECDSA
- **Key Type**: 384-bit prime curve (secp384r1)
- **X.509 v3** certificates with proper extensions

## Features

- ✅ Generate certificates compliant with AMHS profiles
- ✅ Validate certificates against profile requirements
- ✅ Display detailed certificate information
- ✅ Support for custom Subject Alternative Names (MTA Name, X.400 Address)
- ✅ Configurable validity periods
- ✅ Comprehensive validation reports with errors, warnings, and info

## Prerequisites

- Go 1.21 or later
- OpenSSL (for generating the root CA)

## Installation

### 1. Clone or Extract the Project

```bash
cd amhs-pki-demo
```

### 2. Generate the Root CA

First, generate a dummy root CA certificate for testing:

```bash
chmod +x generate-root-ca.sh
./generate-root-ca.sh
```

This creates:
- `root-demo.crt` - Root CA certificate
- `root-demo.key` - Root CA private key

### 3. Build the Tool

```bash
go build -o amhs-pki-demo .
```

## Usage

### Generate Certificates

#### 1. Generate AMHS Issuing CA (Intermediate CA)

```bash
./amhs-pki-demo generate -type ca -output amhs-ca -validity 5475
```

This generates:
- `amhs-ca.crt` - CA certificate (valid for 15 years)
- `amhs-ca.key` - CA private key

**Profile Characteristics:**
- CA: TRUE
- Path Length: 0 (cannot issue sub-CAs)
- Key Usage: digitalSignature, keyCertSign, cRLSign
- Validity: 15 years (5475 days)

#### 2. Generate MTA Certificate

```bash
./amhs-pki-demo generate \
    -type mta \
    -output mta-de-fra1 \
    -subject "MTA-EDDD-1" \
    -validity 730 \
    -mta-name "MTA-EDDD-1"
```

This generates:
- `mta-de-fra1.crt` - MTA certificate
- `mta-de-fra1.key` - MTA private key

**Profile Characteristics:**
- CA: FALSE
- Key Usage: digitalSignature
- Extended Key Usage: clientAuth, serverAuth
- Subject Alternative Name: MTA Name or X.400 Address
- Validity: 1-3 years

#### 3. Generate Signing Certificate (User Agent)

```bash
./amhs-pki-demo generate \
    -type signing \
    -output ua-signing \
    -subject "UA-LFPGZTZX" \
    -validity 730 \
    -x400-address "C=FR;CN=LFPGZTZX;"
```

This generates:
- `ua-signing.crt` - Signing certificate
- `ua-signing.key` - Signing private key

**Profile Characteristics:**
- CA: FALSE
- Key Usage: nonRepudiation (contentCommitment)
- Extended Key Usage: Document Signing (1.3.6.1.5.5.7.3.36 from RFC 9336)
- Subject Alternative Name: X.400 Address
- Validity: 1-3 years

### Validate Certificates

Validate a certificate against its expected profile:

```bash
# Validate CA certificate
./amhs-pki-demo validate -cert amhs-ca.crt -type ca

# Validate MTA certificate
./amhs-pki-demo validate -cert mta-de-fra1.crt -type mta

# Validate Signing certificate
./amhs-pki-demo validate -cert ua-signing.crt -type signing
```

**Validation Output:**
- ✅ **Valid**: Certificate meets all requirements
- ❌ **Errors**: Critical violations of the profile
- ⚠️ **Warnings**: Recommendations or optional fields missing
- ℹ️ **Info**: General information about the certificate

### Display Certificate Information

```bash
./amhs-pki-demo info mta-de-fra1.crt
```

Shows:
- Version, Serial Number, Signature Algorithm
- Issuer and Subject Distinguished Names
- Validity period
- Public key information
- All extensions (Basic Constraints, Key Usage, etc.)

## Certificate Profiles

### CA Certificate Profile

```
Version: 3
Signature Algorithm: SHA-384 with ECDSA
Public Key: 384-bit ECDSA (secp384r1)
Validity: 15 years

Subject:
  CN: AMHS Issuing CA
  OU: Common PKI Services, European Aviation
  O: EUROCONTROL

Extensions:
  - Basic Constraints (critical): CA=TRUE, pathLen=0
  - Key Usage (critical): digitalSignature, keyCertSign, cRLSign
  - Subject Key Identifier
  - Authority Key Identifier
  - Authority Information Access (OCSP, CA Issuers)
  - CRL Distribution Points
  - Certificate Policies
```

### MTA Certificate Profile

```
Version: 3
Signature Algorithm: SHA-384 with ECDSA
Public Key: 384-bit ECDSA (secp384r1)
Validity: 1-3 years

Subject:
  CN: <MTA-ID>
  OU: Common PKI Services, European Aviation
  O: EUROCONTROL

Extensions:
  - Basic Constraints (critical): CA=FALSE
  - Key Usage (critical): digitalSignature
  - Extended Key Usage: clientAuth, serverAuth
  - Subject Alternative Name: MTA Name (OID 2.6.5.6.0) or X.400 Address
  - Subject Key Identifier
  - Authority Key Identifier
  - Authority Information Access (OCSP, CA Issuers)
  - CRL Distribution Points
  - Certificate Policies
```

### Signing Certificate Profile

```
Version: 3
Signature Algorithm: SHA-384 with ECDSA
Public Key: 384-bit ECDSA (secp384r1)
Validity: 1-3 years

Subject:
  CN: <UA/MTCU ID>
  OU: Common PKI Services, European Aviation
  O: EUROCONTROL

Extensions:
  - Basic Constraints (critical): CA=FALSE
  - Key Usage (critical): nonRepudiation (contentCommitment)
  - Extended Key Usage: Document Signing (1.3.6.1.5.5.7.3.36)
  - Subject Alternative Name: X.400 Address
  - Subject Key Identifier
  - Authority Key Identifier
  - Authority Information Access (OCSP, CA Issuers)
  - CRL Distribution Points
  - Certificate Policies
```

## Project Structure

```
amhs-pki-demo/
├── main.go                    # CLI interface
├── go.mod                     # Go module definition
├── generate-root-ca.sh        # Script to generate root CA
├── generator/
│   └── generator.go          # Certificate generation logic
├── validator/
│   └── validator.go          # Certificate validation logic
└── README.md                  # This file

Generated files:
├── root-demo.crt             # Root CA certificate
├── root-demo.key             # Root CA private key
├── amhs-ca.crt               # AMHS Issuing CA certificate
├── amhs-ca.key               # AMHS Issuing CA private key
├── *.crt                     # Generated certificates
└── *.key                     # Generated private keys
```

## Technical Details

### OIDs Used

| Purpose | OID | Description |
|---------|-----|-------------|
| MTA Name | 2.6.5.6.0 | AMHS MTA identifier |
| X.500 Name | 2.5.4.41 | id-at-name |
| Client Auth | 1.3.6.1.5.5.7.3.2 | TLS client authentication |
| Server Auth | 1.3.6.1.5.5.7.3.1 | TLS server authentication |
| Document Signing | 1.3.6.1.5.5.7.3.36 | RFC 9336 document signing |
| Certificate Policy | 1.2.3.4.5.6.7.8.9 | Example/dummy OID |

### Key Usage Mappings

| Certificate Type | Key Usage | Extended Key Usage |
|-----------------|-----------|-------------------|
| CA | digitalSignature, keyCertSign, cRLSign | - |
| MTA | digitalSignature | clientAuth, serverAuth |
| Signing | contentCommitment (nonRepudiation) | Document Signing |

## Customization & Experimentation

This demonstration environment is designed to be easily adaptable for experimentation:

### 1. Modify Certificate Profiles

Edit `generator/generator.go` to adjust:
- Validity periods
- Subject DN components
- Extension values
- OID values

### 2. Add Custom Extensions

```go
template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
    Id:       asn1.ObjectIdentifier{...}, // Your OID
    Critical: false,
    Value:    customValue,
})
```

### 3. Adjust Validation Rules

Edit `validator/validator.go` to:
- Add new validation checks
- Modify severity levels (error vs warning)
- Add custom compliance rules

### 4. Test Interoperability

Generate certificates with different attributes and test with various AMHS implementations to ensure compatibility.

## Contributing

This tool is designed for ICAO and Eurocontrol AMHS PKI standardization efforts. Suggestions and improvements are welcome for:
- Additional certificate profiles
- Enhanced validation rules
- Interoperability testing features
- Documentation improvements

## References

- **ICAO Doc 9880**
- **ICAO Annex 10, Volume II**: Aeronautical Telecommunications
- **RFC 9336**: X.509 Certificate Extended Key Usage for Document Signing
- **RFC 5280**: Internet X.509 Public Key Infrastructure Certificate and CRL Profile

## License

This is a demonstration tool for standardization and testing purposes, not an official product of Indra Group.

All Rights Reserved

Copyright (c) 2025 - Indra Avitech GmbH

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
