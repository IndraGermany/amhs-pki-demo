package validator

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// ValidationResult contains the results of certificate validation
type ValidationResult struct {
	Valid    bool
	Errors   []string
	Warnings []string
	Info     []string
}

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

// ValidateCertificate validates a certificate against a specific profile
func (v *Validator) ValidateCertificate(certFile, certType string) (*ValidationResult, error) {
	cert, err := v.loadCertificate(certFile)
	if err != nil {
		return nil, err
	}

	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
		Info:     []string{},
	}

	switch certType {
	case "ca":
		v.validateCA(cert, result)
	case "mta":
		v.validateMTA(cert, result)
	case "signing":
		v.validateSigning(cert, result)
	default:
		return nil, fmt.Errorf("unknown certificate type: %s", certType)
	}

	result.Valid = len(result.Errors) == 0
	return result, nil
}

func (v *Validator) validateCA(cert *x509.Certificate, result *ValidationResult) {
	result.Info = append(result.Info, "Validating AMHS CA Certificate Profile")

	// Check version
	if cert.Version != 3 {
		result.Errors = append(result.Errors, fmt.Sprintf("Version must be 3, got %d", cert.Version))
	}

	// Check signature algorithm
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		result.Errors = append(result.Errors, fmt.Sprintf("Signature algorithm must be SHA384-ECDSA, got %s", cert.SignatureAlgorithm))
	}

	// Check public key algorithm and curve
	if pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if pubKey.Curve.Params().BitSize != 384 {
			result.Errors = append(result.Errors, fmt.Sprintf("Public key must be secp384r1 (384-bit), got %d-bit", pubKey.Curve.Params().BitSize))
		}
	} else {
		result.Errors = append(result.Errors, "Public key must be ECDSA")
	}

	// Check Basic Constraints
	if !cert.BasicConstraintsValid {
		result.Errors = append(result.Errors, "Basic Constraints extension must be present")
	}
	if !cert.IsCA {
		result.Errors = append(result.Errors, "Certificate must be a CA (IsCA must be TRUE)")
	}
	if cert.MaxPathLen != 0 {
		result.Errors = append(result.Errors, fmt.Sprintf("Path length constraint must be 0, got %d", cert.MaxPathLen))
	}

	// Check Key Usage
	expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&expectedKeyUsage != expectedKeyUsage {
		result.Errors = append(result.Errors, "Key Usage must include: digitalSignature, keyCertSign, cRLSign")
	}

	// Check Subject Key Identifier
	if len(cert.SubjectKeyId) == 0 {
		result.Errors = append(result.Errors, "Subject Key Identifier extension is required")
	} else {
		result.Info = append(result.Info, fmt.Sprintf("Subject Key Identifier present: %x", cert.SubjectKeyId))
	}

	// Check Authority Key Identifier
	if len(cert.AuthorityKeyId) == 0 {
		result.Warnings = append(result.Warnings, "Authority Key Identifier extension is recommended")
	} else {
		result.Info = append(result.Info, fmt.Sprintf("Authority Key Identifier present: %x", cert.AuthorityKeyId))
	}

	// Check Authority Information Access
	if len(cert.OCSPServer) == 0 {
		result.Warnings = append(result.Warnings, "OCSP server URL should be present in AIA")
	} else {
		result.Info = append(result.Info, fmt.Sprintf("OCSP Server: %s", cert.OCSPServer[0]))
	}

	if len(cert.IssuingCertificateURL) == 0 {
		result.Warnings = append(result.Warnings, "Issuing CA URL should be present in AIA")
	} else {
		result.Info = append(result.Info, fmt.Sprintf("Issuing CA URL: %s", cert.IssuingCertificateURL[0]))
	}

	// Check CRL Distribution Points
	if len(cert.CRLDistributionPoints) == 0 {
		result.Warnings = append(result.Warnings, "CRL Distribution Points should be present")
	} else {
		result.Info = append(result.Info, fmt.Sprintf("CRL Distribution Point: %s", cert.CRLDistributionPoints[0]))
	}

	// Check Certificate Policies
	if len(cert.PolicyIdentifiers) == 0 {
		result.Warnings = append(result.Warnings, "Certificate Policy extension should be present")
	} else {
		result.Info = append(result.Info, fmt.Sprintf("Certificate Policy OID: %s", cert.PolicyIdentifiers[0]))
	}

	// Check validity period (should be ~15 years for CA)
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	result.Info = append(result.Info, fmt.Sprintf("Validity period: %d days (~%.1f years)", validityDays, float64(validityDays)/365))
	
	if validityDays < 5400 || validityDays > 5550 {
		result.Warnings = append(result.Warnings, "CA certificate validity should be approximately 15 years (5475 days)")
	}

	// Check Subject DN
	if cert.Subject.CommonName == "" {
		result.Errors = append(result.Errors, "Subject CN is required")
	}
	result.Info = append(result.Info, fmt.Sprintf("Subject: %s", cert.Subject))
}

func (v *Validator) validateMTA(cert *x509.Certificate, result *ValidationResult) {
	result.Info = append(result.Info, "Validating AMHS MTA Certificate Profile")

	// Check version
	if cert.Version != 3 {
		result.Errors = append(result.Errors, fmt.Sprintf("Version must be 3, got %d", cert.Version))
	}

	// Check signature algorithm
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		result.Errors = append(result.Errors, fmt.Sprintf("Signature algorithm must be SHA384-ECDSA, got %s", cert.SignatureAlgorithm))
	}

	// Check public key
	if pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if pubKey.Curve.Params().BitSize != 384 {
			result.Errors = append(result.Errors, fmt.Sprintf("Public key must be secp384r1 (384-bit), got %d-bit", pubKey.Curve.Params().BitSize))
		}
	} else {
		result.Errors = append(result.Errors, "Public key must be ECDSA")
	}

	// Check Basic Constraints
	if !cert.BasicConstraintsValid {
		result.Errors = append(result.Errors, "Basic Constraints extension must be present")
	}
	if cert.IsCA {
		result.Errors = append(result.Errors, "Certificate must not be a CA (IsCA must be FALSE)")
	}

	// Check Key Usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		result.Errors = append(result.Errors, "Key Usage must include digitalSignature")
	}

	// Check Extended Key Usage
	hasClientAuth := false
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasClientAuth {
		result.Errors = append(result.Errors, "Extended Key Usage must include clientAuth")
	}
	if !hasServerAuth {
		result.Errors = append(result.Errors, "Extended Key Usage must include serverAuth")
	}

	// Check extensions
	if len(cert.SubjectKeyId) == 0 {
		result.Errors = append(result.Errors, "Subject Key Identifier extension is required")
	}

	if len(cert.AuthorityKeyId) == 0 {
		result.Warnings = append(result.Warnings, "Authority Key Identifier extension is recommended")
	}

	// Check AIA
	if len(cert.OCSPServer) == 0 {
		result.Warnings = append(result.Warnings, "OCSP server URL should be present")
	}
	if len(cert.IssuingCertificateURL) == 0 {
		result.Warnings = append(result.Warnings, "Issuing CA URL should be present")
	}

	// Check CRL Distribution Points
	if len(cert.CRLDistributionPoints) == 0 {
		result.Warnings = append(result.Warnings, "CRL Distribution Points should be present")
	}

	// Check Certificate Policies
	if len(cert.PolicyIdentifiers) == 0 {
		result.Warnings = append(result.Warnings, "Certificate Policy should be present")
	}

	// Check validity (1-3 years typical for MTA)
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	result.Info = append(result.Info, fmt.Sprintf("Validity period: %d days (~%.1f years)", validityDays, float64(validityDays)/365))
	
	if validityDays > 1095 {
		result.Warnings = append(result.Warnings, "MTA certificate validity should typically be 1-3 years")
	}

	// Check for Subject Alternative Name
	if len(cert.DNSNames) == 0 && len(cert.EmailAddresses) == 0 {
		// Check for custom SAN in extensions
		hasSAN := false
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
				hasSAN = true
				result.Info = append(result.Info, "Subject Alternative Name extension present (custom format)")
				break
			}
		}
		if !hasSAN {
			result.Warnings = append(result.Warnings, "Subject Alternative Name with MTA Name or X.400 Address is recommended")
		}
	}

	result.Info = append(result.Info, fmt.Sprintf("Subject: %s", cert.Subject))
}

func (v *Validator) validateSigning(cert *x509.Certificate, result *ValidationResult) {
	result.Info = append(result.Info, "Validating AMHS Signing Certificate Profile")

	// Check version
	if cert.Version != 3 {
		result.Errors = append(result.Errors, fmt.Sprintf("Version must be 3, got %d", cert.Version))
	}

	// Check signature algorithm
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		result.Errors = append(result.Errors, fmt.Sprintf("Signature algorithm must be SHA384-ECDSA, got %s", cert.SignatureAlgorithm))
	}

	// Check public key
	if pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if pubKey.Curve.Params().BitSize != 384 {
			result.Errors = append(result.Errors, fmt.Sprintf("Public key must be secp384r1 (384-bit), got %d-bit", pubKey.Curve.Params().BitSize))
		}
	} else {
		result.Errors = append(result.Errors, "Public key must be ECDSA")
	}

	// Check Basic Constraints
	if !cert.BasicConstraintsValid {
		result.Errors = append(result.Errors, "Basic Constraints extension must be present")
	}
	if cert.IsCA {
		result.Errors = append(result.Errors, "Certificate must not be a CA (IsCA must be FALSE)")
	}

	// Check Key Usage - must include nonRepudiation (contentCommitment)
	if cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		result.Errors = append(result.Errors, "Key Usage must include nonRepudiation (contentCommitment)")
	}

	// Check for Document Signing EKU (1.3.6.1.5.5.7.3.36)
	hasDocSigning := false
	docSignOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}
	
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) { // EKU extension
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &oids); err == nil {
				for _, oid := range oids {
					if oid.Equal(docSignOID) {
						hasDocSigning = true
						break
					}
				}
			}
		}
	}
	
	if !hasDocSigning {
		result.Errors = append(result.Errors, "Extended Key Usage must include Document Signing (1.3.6.1.5.5.7.3.36)")
	} else {
		result.Info = append(result.Info, "Document Signing EKU present (RFC 9336)")
	}

	// Check extensions
	if len(cert.SubjectKeyId) == 0 {
		result.Errors = append(result.Errors, "Subject Key Identifier extension is required")
	}

	if len(cert.AuthorityKeyId) == 0 {
		result.Warnings = append(result.Warnings, "Authority Key Identifier extension is recommended")
	}

	// Check AIA
	if len(cert.OCSPServer) == 0 {
		result.Warnings = append(result.Warnings, "OCSP server URL should be present")
	}
	if len(cert.IssuingCertificateURL) == 0 {
		result.Warnings = append(result.Warnings, "Issuing CA URL should be present")
	}

	// Check CRL Distribution Points
	if len(cert.CRLDistributionPoints) == 0 {
		result.Warnings = append(result.Warnings, "CRL Distribution Points should be present")
	}

	// Check Certificate Policies
	if len(cert.PolicyIdentifiers) == 0 {
		result.Warnings = append(result.Warnings, "Certificate Policy should be present")
	}

	// Check validity (1-3 years typical)
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	result.Info = append(result.Info, fmt.Sprintf("Validity period: %d days (~%.1f years)", validityDays, float64(validityDays)/365))
	
	if validityDays > 1095 {
		result.Warnings = append(result.Warnings, "Signing certificate validity should typically be 1-3 years")
	}

	result.Info = append(result.Info, fmt.Sprintf("Subject: %s", cert.Subject))
}

// DisplayCertificateInfo displays detailed information about a certificate
func (v *Validator) DisplayCertificateInfo(certFile string) (string, error) {
	cert, err := v.loadCertificate(certFile)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("Version: %d\n", cert.Version))
	sb.WriteString(fmt.Sprintf("Serial Number: %s\n", cert.SerialNumber))
	sb.WriteString(fmt.Sprintf("Signature Algorithm: %s\n\n", cert.SignatureAlgorithm))
	
	sb.WriteString("Issuer:\n")
	sb.WriteString(fmt.Sprintf("  CN: %s\n", cert.Issuer.CommonName))
	if len(cert.Issuer.Organization) > 0 {
		sb.WriteString(fmt.Sprintf("  O: %s\n", strings.Join(cert.Issuer.Organization, ", ")))
	}
	if len(cert.Issuer.OrganizationalUnit) > 0 {
		sb.WriteString(fmt.Sprintf("  OU: %s\n", strings.Join(cert.Issuer.OrganizationalUnit, ", ")))
	}
	sb.WriteString("\n")
	
	sb.WriteString("Subject:\n")
	sb.WriteString(fmt.Sprintf("  CN: %s\n", cert.Subject.CommonName))
	if len(cert.Subject.Organization) > 0 {
		sb.WriteString(fmt.Sprintf("  O: %s\n", strings.Join(cert.Subject.Organization, ", ")))
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		sb.WriteString(fmt.Sprintf("  OU: %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", ")))
	}
	sb.WriteString("\n")
	
	sb.WriteString("Validity:\n")
	sb.WriteString(fmt.Sprintf("  Not Before: %s\n", cert.NotBefore))
	sb.WriteString(fmt.Sprintf("  Not After: %s\n", cert.NotAfter))
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	sb.WriteString(fmt.Sprintf("  Days: %d (~%.1f years)\n\n", validityDays, float64(validityDays)/365))
	
	if pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		sb.WriteString("Public Key:\n")
		sb.WriteString(fmt.Sprintf("  Algorithm: ECDSA\n"))
		sb.WriteString(fmt.Sprintf("  Curve: %s (%d-bit)\n\n", pubKey.Curve.Params().Name, pubKey.Curve.Params().BitSize))
	}
	
	sb.WriteString("Extensions:\n")
	
	if cert.BasicConstraintsValid {
		sb.WriteString(fmt.Sprintf("  Basic Constraints (critical): CA=%t", cert.IsCA))
		if cert.IsCA {
			sb.WriteString(fmt.Sprintf(", pathLen=%d", cert.MaxPathLen))
		}
		sb.WriteString("\n")
	}
	
	if cert.KeyUsage != 0 {
		sb.WriteString("  Key Usage (critical): ")
		usages := []string{}
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			usages = append(usages, "digitalSignature")
		}
		if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
			usages = append(usages, "contentCommitment")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
			usages = append(usages, "keyCertSign")
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
			usages = append(usages, "cRLSign")
		}
		sb.WriteString(strings.Join(usages, ", "))
		sb.WriteString("\n")
	}
	
	if len(cert.ExtKeyUsage) > 0 {
		sb.WriteString("  Extended Key Usage: ")
		ekus := []string{}
		for _, eku := range cert.ExtKeyUsage {
			switch eku {
			case x509.ExtKeyUsageClientAuth:
				ekus = append(ekus, "clientAuth")
			case x509.ExtKeyUsageServerAuth:
				ekus = append(ekus, "serverAuth")
			default:
				ekus = append(ekus, fmt.Sprintf("unknown(%d)", eku))
			}
		}
		sb.WriteString(strings.Join(ekus, ", "))
		sb.WriteString("\n")
	}
	
	if len(cert.SubjectKeyId) > 0 {
		sb.WriteString(fmt.Sprintf("  Subject Key Identifier: %x\n", cert.SubjectKeyId))
	}
	
	if len(cert.AuthorityKeyId) > 0 {
		sb.WriteString(fmt.Sprintf("  Authority Key Identifier: %x\n", cert.AuthorityKeyId))
	}
	
	if len(cert.OCSPServer) > 0 {
		sb.WriteString(fmt.Sprintf("  OCSP Server: %s\n", cert.OCSPServer[0]))
	}
	
	if len(cert.IssuingCertificateURL) > 0 {
		sb.WriteString(fmt.Sprintf("  CA Issuers: %s\n", cert.IssuingCertificateURL[0]))
	}
	
	if len(cert.CRLDistributionPoints) > 0 {
		sb.WriteString(fmt.Sprintf("  CRL Distribution Points: %s\n", cert.CRLDistributionPoints[0]))
	}
	
	if len(cert.PolicyIdentifiers) > 0 {
		sb.WriteString(fmt.Sprintf("  Certificate Policies: %s\n", cert.PolicyIdentifiers[0]))
	}
	
	return sb.String(), nil
}

func (v *Validator) loadCertificate(certFile string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}
