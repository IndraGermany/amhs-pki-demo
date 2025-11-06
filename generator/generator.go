package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	RootCertFile = "root-demo.crt"
	RootKeyFile  = "root-demo.key"
)

// OIDs for AMHS extensions
var (
	// OID for MTA Name (2.6.5.6.0)
	OIDMTAName = asn1.ObjectIdentifier{2, 6, 5, 6, 0}
	
	// OID for id-at-name (2.5.4.41) - X.500 name
	OIDAtName = asn1.ObjectIdentifier{2, 5, 4, 41}
	
	// Enhanced Key Usage OIDs
	OIDClientAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	OIDServerAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	OIDDocumentSigning  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36} // RFC 9336
	
	// Certificate Policy OID (example/dummy as specified)
	OIDCertificatePolicy = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9} // Example OID
	
	// Authority Information Access
	OIDAuthorityInfoAccessOcsp   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	OIDAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

type Generator struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
}

func NewGenerator() *Generator {
	return &Generator{}
}

// loadRootCA loads the root CA certificate and key
func (g *Generator) loadRootCA() error {
	if g.rootCert != nil {
		return nil // Already loaded
	}

	// Load root certificate
	certPEM, err := os.ReadFile(RootCertFile)
	if err != nil {
		return fmt.Errorf("failed to read root certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode root certificate PEM")
	}

	g.rootCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root certificate: %v", err)
	}

	// Load root key
	keyPEM, err := os.ReadFile(RootKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read root key: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode root key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root key: %v", err)
	}

	g.rootKey = key
	return nil
}

// GenerateCA generates an AMHS Issuing CA certificate
func (g *Generator) GenerateCA(outputPrefix, subjectCN string, validityDays int) error {
	if err := g.loadRootCA(); err != nil {
		return err
	}

	if subjectCN == "" {
		subjectCN = "AMHS Issuing CA"
	}

	// Generate key pair (secp384r1)
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Generate random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Calculate Subject Key Identifier (SHA1 of public key)
	pubKeyBytes := elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	ski := sha1.Sum(pubKeyBytes)

	// Calculate Authority Key Identifier (SHA1 of issuer's public key)
	issuerPubKeyBytes := elliptic.Marshal(g.rootKey.PublicKey.Curve, g.rootKey.PublicKey.X, g.rootKey.PublicKey.Y)
	aki := sha1.Sum(issuerPubKeyBytes)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         subjectCN,
			OrganizationalUnit: []string{"Common PKI Services", "European Aviation"},
			Organization:       []string{"EUROCONTROL"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        aki[:],
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		
		// Authority Information Access
		OCSPServer:       []string{"http://ocsp.harica.gr"},
		IssuingCertificateURL: []string{"http://repo.harica.gr/certs/EACP-Root-RSA/RootCA.crt"},
		
		// CRL Distribution Points
		CRLDistributionPoints: []string{"http://crl.harica.gr/EACP-Root-RSA/ECC.crl"},
		
		// Certificate Policy
		PolicyIdentifiers: []asn1.ObjectIdentifier{OIDCertificatePolicy},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, g.rootCert, &privateKey.PublicKey, g.rootKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save certificate
	if err := saveCertificate(outputPrefix+".crt", certDER); err != nil {
		return err
	}

	// Save private key
	if err := savePrivateKey(outputPrefix+".key", privateKey); err != nil {
		return err
	}

	return nil
}

// GenerateMTA generates an MTA certificate
func (g *Generator) GenerateMTA(outputPrefix, subjectCN string, validityDays int, mtaName, x400Address string) error {
	// Load issuing CA instead of root
	issuerCert, issuerKey, err := g.loadIssuerCA()
	if err != nil {
		return fmt.Errorf("failed to load issuing CA: %v (generate CA first)", err)
	}

	if subjectCN == "" {
		subjectCN = "AMHS MTA"
	}

	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	pubKeyBytes := elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	ski := sha1.Sum(pubKeyBytes)

	issuerPubKeyBytes := elliptic.Marshal(issuerKey.PublicKey.Curve, issuerKey.PublicKey.X, issuerKey.PublicKey.Y)
	aki := sha1.Sum(issuerPubKeyBytes)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         subjectCN,
			OrganizationalUnit: []string{"Common PKI Services", "European Aviation"},
			Organization:       []string{"EUROCONTROL"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        aki[:],
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		
		OCSPServer:       []string{"http://ocsp.harica.gr"},
		IssuingCertificateURL: []string{"http://repo.harica.gr/certs/EACP-AMHS/AMHS-IssuingCA.crt"},
		CRLDistributionPoints: []string{"http://crl.harica.gr/EACP-AMHS/AMHS-IssuingCA.crl"},
		PolicyIdentifiers: []asn1.ObjectIdentifier{OIDCertificatePolicy},
	}

	// Add Subject Alternative Names
	if mtaName != "" || x400Address != "" {
		template.ExtraExtensions = []pkix.Extension{}
		
		if mtaName != "" {
			// Add MTA Name as OtherName
			mtaNameValue, err := asn1.Marshal(mtaName)
			if err != nil {
				return fmt.Errorf("failed to marshal MTA name: %v", err)
			}
			
			otherName := struct {
				OID   asn1.ObjectIdentifier
				Value asn1.RawValue `asn1:"tag:0,explicit"`
			}{
				OID: OIDMTAName,
				Value: asn1.RawValue{
					Tag:   0,
					Class: asn1.ClassContextSpecific,
					Bytes: mtaNameValue,
				},
			}
			
			otherNameBytes, err := asn1.Marshal(otherName)
			if err != nil {
				return fmt.Errorf("failed to marshal other name: %v", err)
			}
			
			// Wrap in GeneralName with tag [0]
			generalName := asn1.RawValue{
				Tag:   0,
				Class: asn1.ClassContextSpecific,
				Bytes: otherNameBytes,
			}
			
			sanSequence := []asn1.RawValue{generalName}
			sanBytes, err := asn1.Marshal(sanSequence)
			if err != nil {
				return fmt.Errorf("failed to marshal SAN: %v", err)
			}
			
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // SAN OID
				Value: sanBytes,
			})
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &privateKey.PublicKey, issuerKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	if err := saveCertificate(outputPrefix+".crt", certDER); err != nil {
		return err
	}

	if err := savePrivateKey(outputPrefix+".key", privateKey); err != nil {
		return err
	}

	return nil
}

// GenerateSigning generates a signing certificate (for UA/MTCU)
func (g *Generator) GenerateSigning(outputPrefix, subjectCN string, validityDays int, x400Address string) error {
	issuerCert, issuerKey, err := g.loadIssuerCA()
	if err != nil {
		return fmt.Errorf("failed to load issuing CA: %v (generate CA first)", err)
	}

	if subjectCN == "" {
		subjectCN = "AMHS User Agent"
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	pubKeyBytes := elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	ski := sha1.Sum(pubKeyBytes)

	issuerPubKeyBytes := elliptic.Marshal(issuerKey.PublicKey.Curve, issuerKey.PublicKey.X, issuerKey.PublicKey.Y)
	aki := sha1.Sum(issuerPubKeyBytes)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         subjectCN,
			OrganizationalUnit: []string{"Common PKI Services", "European Aviation"},
			Organization:       []string{"EUROCONTROL"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageContentCommitment, // nonRepudiation
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        aki[:],
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		
		OCSPServer:       []string{"http://ocsp.harica.gr"},
		IssuingCertificateURL: []string{"http://repo.harica.gr/certs/EACP-AMHS/AMHS-IssuingCA.crt"},
		CRLDistributionPoints: []string{"http://crl.harica.gr/EACP-AMHS/AMHS-IssuingCA.crl"},
		PolicyIdentifiers: []asn1.ObjectIdentifier{OIDCertificatePolicy},
	}

	// Add Document Signing EKU
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // Extended Key Usage OID
			Critical: false,
			Value: func() []byte {
				ekuBytes, _ := asn1.Marshal([]asn1.ObjectIdentifier{OIDDocumentSigning})
				return ekuBytes
			}(),
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &privateKey.PublicKey, issuerKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	if err := saveCertificate(outputPrefix+".crt", certDER); err != nil {
		return err
	}

	if err := savePrivateKey(outputPrefix+".key", privateKey); err != nil {
		return err
	}

	return nil
}

// loadIssuerCA attempts to load the AMHS Issuing CA
func (g *Generator) loadIssuerCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Try to load amhs-ca.crt and amhs-ca.key
	certFiles := []string{"amhs-ca.crt", "issuing-ca.crt"}
	keyFiles := []string{"amhs-ca.key", "issuing-ca.key"}

	var certPEM []byte
	var keyPEM []byte
	var err error

	for i, certFile := range certFiles {
		certPEM, err = os.ReadFile(certFile)
		if err == nil {
			keyPEM, err = os.ReadFile(keyFiles[i])
			if err == nil {
				break
			}
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("issuing CA not found")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse key: %v", err)
	}

	return cert, key, nil
}

func saveCertificate(filename string, certDER []byte) error {
	certOut, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	return nil
}

func savePrivateKey(filename string, key *ecdsa.PrivateKey) error {
	keyOut, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	return nil
}
