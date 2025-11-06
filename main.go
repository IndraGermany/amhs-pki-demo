package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"amhs-pki-demo/generator"
	"amhs-pki-demo/validator"
)

func main() {
	// Command flags
	generateCmd := flag.NewFlagSet("generate", flag.ExitOnError)
	validateCmd := flag.NewFlagSet("validate", flag.ExitOnError)

	// Generate command flags
	genType := generateCmd.String("type", "", "Certificate type: ca, mta, signing")
	genOutput := generateCmd.String("output", "", "Output file prefix (e.g., 'test' creates test.crt and test.key)")
	genSubject := generateCmd.String("subject", "", "Subject CN")
	genValidity := generateCmd.Int("validity", 365, "Validity period in days")
	genMTAName := generateCmd.String("mta-name", "", "MTA Name for SAN (MTA certificates only)")
	genX400Addr := generateCmd.String("x400-address", "", "X.400 Address for SAN")

	// Validate command flags
	valCert := validateCmd.String("cert", "", "Certificate file to validate")
	valType := validateCmd.String("type", "", "Expected certificate type: ca, mta, signing")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		generateCmd.Parse(os.Args[2:])
		if *genType == "" || *genOutput == "" {
			fmt.Println("Error: -type and -output are required")
			generateCmd.PrintDefaults()
			os.Exit(1)
		}
		handleGenerate(*genType, *genOutput, *genSubject, *genValidity, *genMTAName, *genX400Addr)

	case "validate":
		validateCmd.Parse(os.Args[2:])
		if *valCert == "" || *valType == "" {
			fmt.Println("Error: -cert and -type are required")
			validateCmd.PrintDefaults()
			os.Exit(1)
		}
		handleValidate(*valCert, *valType)

	case "info":
		if len(os.Args) < 3 {
			fmt.Println("Error: certificate file required")
			os.Exit(1)
		}
		handleInfo(os.Args[2])

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("AMHS PKI Demonstration Tool")
	fmt.Println("\nUsage:")
	fmt.Println("  amhs-pki-demo generate -type <ca|mta|signing> -output <prefix> [options]")
	fmt.Println("  amhs-pki-demo validate -cert <file> -type <ca|mta|signing>")
	fmt.Println("  amhs-pki-demo info <certificate-file>")
	fmt.Println("\nGenerate Options:")
	fmt.Println("  -type string       Certificate type: ca, mta, signing")
	fmt.Println("  -output string     Output file prefix")
	fmt.Println("  -subject string    Subject CN (optional)")
	fmt.Println("  -validity int      Validity period in days (default 365)")
	fmt.Println("  -mta-name string   MTA Name for SAN (MTA certificates)")
	fmt.Println("  -x400-address      X.400 Address for SAN")
	fmt.Println("\nValidate Options:")
	fmt.Println("  -cert string       Certificate file to validate")
	fmt.Println("  -type string       Expected certificate type")
	fmt.Println("\nExamples:")
	fmt.Println("  # Generate CA certificate")
	fmt.Println("  amhs-pki-demo generate -type ca -output amhs-ca -validity 5475")
	fmt.Println("")
	fmt.Println("  # Generate MTA certificate")
	fmt.Println("  amhs-pki-demo generate -type mta -output mta-paris -subject \"LFPGZTZX\" -mta-name \"LFPGZTZX\"")
	fmt.Println("")
	fmt.Println("  # Validate certificate")
	fmt.Println("  amhs-pki-demo validate -cert mta-paris.crt -type mta")
}

func handleGenerate(certType, output, subject string, validity int, mtaName, x400Addr string) {
	gen := generator.NewGenerator()

	var err error
	switch certType {
	case "ca":
		err = gen.GenerateCA(output, subject, validity)
	case "mta":
		err = gen.GenerateMTA(output, subject, validity, mtaName, x400Addr)
	case "signing":
		err = gen.GenerateSigning(output, subject, validity, x400Addr)
	default:
		log.Fatalf("Unknown certificate type: %s", certType)
	}

	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	fmt.Printf("Successfully generated %s certificate:\n", certType)
	fmt.Printf("  Certificate: %s.crt\n", output)
	fmt.Printf("  Private Key: %s.key\n", output)
}

func handleValidate(certFile, certType string) {
	val := validator.NewValidator()

	result, err := val.ValidateCertificate(certFile, certType)
	if err != nil {
		log.Fatalf("Validation error: %v", err)
	}

	fmt.Println("Validation Results:")
	fmt.Println("==================")
	fmt.Printf("Certificate Type: %s\n", certType)
	fmt.Printf("Valid: %t\n\n", result.Valid)

	if len(result.Errors) > 0 {
		fmt.Println("Errors:")
		for _, err := range result.Errors {
			fmt.Printf("  ❌ %s\n", err)
		}
		fmt.Println()
	}

	if len(result.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, warn := range result.Warnings {
			fmt.Printf("  ⚠️  %s\n", warn)
		}
		fmt.Println()
	}

	if len(result.Info) > 0 {
		fmt.Println("Information:")
		for _, info := range result.Info {
			fmt.Printf("  ℹ️  %s\n", info)
		}
	}
}

func handleInfo(certFile string) {
	val := validator.NewValidator()
	info, err := val.DisplayCertificateInfo(certFile)
	if err != nil {
		log.Fatalf("Failed to read certificate: %v", err)
	}

	fmt.Println("Certificate Information:")
	fmt.Println("=======================")
	fmt.Print(info)
}
