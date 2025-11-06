# AMHS PKI Configuration Reference

## Object Identifiers (OIDs)

### AMHS-Specific OIDs

| Name | OID | Usage | Source |
|------|-----|-------|--------|
| MTA Name | 2.6.5.6.0 | Subject Alternative Name for MTA identification | AMHS Spec |
| id-at-name | 2.5.4.41 | X.500 directory name attribute | X.500 |

### Extended Key Usage OIDs

| Name | OID | Usage | Source |
|------|-----|-------|--------|
| Server Authentication | 1.3.6.1.5.5.7.3.1 | TLS server auth | RFC 5280 |
| Client Authentication | 1.3.6.1.5.5.7.3.2 | TLS client auth | RFC 5280 |
| Document Signing | 1.3.6.1.5.5.7.3.36 | Document signature verification | RFC 9336 |

### Authority Information Access OIDs

| Name | OID | Usage | Source |
|------|-----|-------|--------|
| OCSP | 1.3.6.1.5.5.7.48.1 | Online Certificate Status Protocol | RFC 5280 |
| CA Issuers | 1.3.6.1.5.5.7.48.2 | CA certificate location | RFC 5280 |

### Certificate Extension OIDs

| Name | OID | Critical | Usage |
|------|-----|----------|-------|
| Subject Key Identifier | 2.5.29.14 | No | SHA-1 hash of public key |
| Key Usage | 2.5.29.15 | Yes | Key usage restrictions |
| Subject Alternative Name | 2.5.29.17 | No | Alternative subject identifiers |
| Basic Constraints | 2.5.29.19 | Yes | CA certificate indicator |
| Authority Key Identifier | 2.5.29.35 | No | Issuer's key identifier |
| Extended Key Usage | 2.5.29.37 | No | Extended purposes |

### Certificate Policy OIDs

| Name | OID | Notes |
|------|-----|-------|
| Example Policy | 1.2.3.4.5.6.7.8.9 | Placeholder - should be replaced with actual policy OID |

## Cryptographic Parameters

### Algorithms

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Signature | ECDSA with SHA-384 | Curve: secp384r1 (NIST P-384) |
| Public Key | ECDSA | Curve: secp384r1, 384-bit |
| Hash (SKI/AKI) | SHA-1 | 160-bit output |

### Key Sizes

| Key Type | Size | Curve |
|----------|------|-------|
| Root CA | 384-bit | secp384r1 |
| Issuing CA | 384-bit | secp384r1 |
| MTA | 384-bit | secp384r1 |
| Signing | 384-bit | secp384r1 |

## Certificate Validity Periods

| Certificate Type | Recommended Period | Configurable Range |
|-----------------|-------------------|-------------------|
| Root CA | 20 years (7300 days) | 10-30 years |
| Issuing CA | 15 years (5475 days) | 10-20 years |
| MTA | 2 years (730 days) | 1-3 years |
| Signing | 2 years (730 days) | 1-3 years |

## Key Usage Combinations

### CA Certificate
```
Key Usage (Critical):
  - digitalSignature
  - keyCertSign
  - cRLSign

Extended Key Usage: None
```

### MTA Certificate
```
Key Usage (Critical):
  - digitalSignature

Extended Key Usage:
  - clientAuth (1.3.6.1.5.5.7.3.2)
  - serverAuth (1.3.6.1.5.5.7.3.1)
```

### Signing Certificate
```
Key Usage (Critical):
  - nonRepudiation (contentCommitment)

Extended Key Usage:
  - Document Signing (1.3.6.1.5.5.7.3.36)
```

## Subject Distinguished Name (DN) Structure

### CA Certificate
```
CN: AMHS Issuing CA
OU: Common PKI Services
OU: European Aviation
O: EUROCONTROL
```

### MTA Certificate
```
CN: <MTA-ID> (e.g., LFPGZTZX)
OU: Common PKI Services
OU: European Aviation
O: EUROCONTROL
```

### Signing Certificate
```
CN: <UA/MTCU-ID> (e.g., UA-LFPGZTZX)
OU: Common PKI Services
OU: European Aviation
O: EUROCONTROL
```

## Authority Information Access (AIA) URLs

### OCSP Responder
```
URL: http://ocsp.harica.gr
Method: OCSP (1.3.6.1.5.5.7.48.1)
```

### CA Issuers

#### Root CA
```
URL: http://repo.harica.gr/certs/EACP-Root-RSA/RootCA.crt
Method: CA Issuers (1.3.6.1.5.5.7.48.2)
```

#### Issuing CA
```
URL: http://repo.harica.gr/certs/EACP-AMHS/AMHS-IssuingCA.crt
Method: CA Issuers (1.3.6.1.5.5.7.48.2)
```

## CRL Distribution Points

### Root CA
```
URL: http://crl.harica.gr/EACP-Root-RSA/ECC.crl
```

### Issuing CA
```
URL: http://crl.harica.gr/EACP-AMHS/AMHS-IssuingCA.crl
```

## Subject Alternative Name (SAN) Formats

### MTA Certificate

#### Option 1: MTA Name (OtherName)
```
OtherName with:
  - OID: 2.6.5.6.0
  - Value: MTA identifier (e.g., "LFPGZTZX")
```

#### Option 2: X.400 Address
```
x400Address format
```

#### Option 3: Directory Name
```
DirectoryName with:
  - OID: 2.5.4.41 (id-at-name)
```

### Signing Certificate

#### X.400 Address
```
X.400 Address format identifying User Agent or MTCU
Example: C=FR;ADMD=ATLAS;PRMD=LFPG;O=DGAC;
```

## Basic Constraints

### CA Certificate
```
Basic Constraints (Critical):
  CA: TRUE
  pathLenConstraint: 0
```

### End-Entity Certificates (MTA, Signing)
```
Basic Constraints (Critical):
  CA: FALSE
```

## Serial Number Generation

All certificates use cryptographically random serial numbers:
- Size: 128 bits
- Generation: crypto/rand (Go's cryptographic random number generator)

## Certificate File Formats

### Private Keys
```
Format: PEM
Type: EC PRIVATE KEY
Encoding: PKCS#8 or SEC1
```

### Certificates
```
Format: PEM
Type: CERTIFICATE
Encoding: DER (X.509)
```

## Extension Encoding

All extensions follow ASN.1 DER encoding as specified in:
- ITU-T X.690 (ASN.1 encoding rules)
- RFC 5280 (PKIX Certificate and CRL Profile)

## Compliance Standards

- **ICAO Annex 10, Volume II**: Aeronautical Telecommunications
- **RFC 5280**: Internet X.509 Public Key Infrastructure
- **RFC 9336**: X.509 Certificate Extended Key Usage for Document Signing
- **RFC 5480**: Elliptic Curve Cryptography Subject Public Key Information
- **RFC 5758**: Internet X.509 PKI Algorithms using SHA-2

## Implementation Notes

### Go Crypto Libraries
- `crypto/x509`: Certificate parsing and generation
- `crypto/ecdsa`: ECDSA key generation and operations
- `crypto/elliptic`: Elliptic curve operations (P-384)
- `encoding/asn1`: ASN.1 encoding/decoding

### Custom Extensions
Custom extensions (e.g., MTA Name SAN) are implemented using:
```go
template.ExtraExtensions = []pkix.Extension{
    {
        Id:       asn1.ObjectIdentifier{...},
        Critical: false,
        Value:    encodedValue,
    },
}
```

### ASN.1 Encoding Considerations
- OtherName in SAN requires explicit tagging
- Sequence of GeneralNames for SAN
- EXPLICIT tag [0] for context-specific types

## Testing and Validation

### Validation Levels

1. **Errors**: Critical violations that prevent certificate use
2. **Warnings**: Deviations from best practices
3. **Info**: Informational messages about certificate contents

### OpenSSL Verification Commands

```bash
# View certificate
openssl x509 -in cert.crt -text -noout

# Verify certificate chain
openssl verify -CAfile root-demo.crt -untrusted amhs-ca.crt cert.crt

# Check key usage
openssl x509 -in cert.crt -noout -ext keyUsage,extendedKeyUsage

# View all extensions
openssl x509 -in cert.crt -noout -ext subjectAltName,basicConstraints
```

## Customization Points

### For Experimentation

1. **Validity Periods**: Adjust via `-validity` flag
2. **Subject CN**: Adjust via `-subject` flag
3. **MTA Names**: Adjust via `-mta-name` flag
4. **X.400 Addresses**: Adjust via `-x400-address` flag
5. **Certificate Policies**: Edit OIDCertificatePolicy in generator.go
6. **URL Endpoints**: Edit AIA and CRL URLs in generator.go

### For Production Use

Replace the following with production values:
- Certificate Policy OIDs
- OCSP responder URLs
- CRL distribution point URLs
- CA certificate repository URLs
- Root CA certificate
