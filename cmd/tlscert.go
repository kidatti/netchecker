package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"netchecker/pkg/tlscert"
)

func RunTLSCert(args []string) {
	fs := flag.NewFlagSet("tlscert", flag.ExitOnError)
	port := fs.String("port", "443", "TLS port")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: netchecker tlscert [-port 443] <host>\n")
		os.Exit(1)
	}

	host := fs.Arg(0)
	result := tlscert.Check(host, *port)

	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "tlscert: %s\n", result.Error)
		os.Exit(1)
	}

	fmt.Printf("TLS Certificate Check: %s:%s\n", result.Host, result.Port)
	fmt.Printf("TLS Version:   %s\n", result.TLSVersion)
	fmt.Printf("Cipher Suite:  %s\n", result.CipherSuite)
	if result.Valid {
		fmt.Printf("Validation:    VALID\n")
	} else {
		fmt.Printf("Validation:    INVALID - %s\n", result.ValidationError)
	}
	fmt.Printf("Check Time:    %s\n", result.CheckTime)

	for i, cert := range result.Certificates {
		fmt.Println()
		if i == 0 {
			fmt.Printf("--- Server Certificate ---\n")
		} else {
			fmt.Printf("--- Chain Certificate #%d ---\n", i)
		}
		printSubject("Subject", cert.Subject)
		printSubject("Issuer", cert.Issuer)
		fmt.Printf("  Serial:      %s\n", cert.SerialNumber)
		fmt.Printf("  Not Before:  %s\n", cert.NotBefore)
		fmt.Printf("  Not After:   %s\n", cert.NotAfter)
		fmt.Printf("  Days Left:   %d\n", cert.DaysUntilExpiry)
		if cert.ExpiryWarning != "" {
			fmt.Printf("  WARNING:     %s\n", cert.ExpiryWarning)
		}
		fmt.Printf("  Signature:   %s\n", cert.SignatureAlgorithm)
		fmt.Printf("  Public Key:  %s %d bits\n", cert.PublicKeyAlgorithm, cert.PublicKeySize)
		fmt.Printf("  Is CA:       %v\n", cert.IsCA)
		fmt.Printf("  Version:     %d\n", cert.Version)

		if len(cert.SANs.DNS) > 0 {
			fmt.Printf("  SAN DNS:     %s\n", strings.Join(cert.SANs.DNS, ", "))
		}
		if len(cert.SANs.IPs) > 0 {
			fmt.Printf("  SAN IPs:     %s\n", strings.Join(cert.SANs.IPs, ", "))
		}
		if len(cert.SANs.Email) > 0 {
			fmt.Printf("  SAN Email:   %s\n", strings.Join(cert.SANs.Email, ", "))
		}
		if len(cert.SANs.URIs) > 0 {
			fmt.Printf("  SAN URIs:    %s\n", strings.Join(cert.SANs.URIs, ", "))
		}
	}
}

func printSubject(label string, s tlscert.SubjectInfo) {
	parts := []string{}
	if s.CommonName != "" {
		parts = append(parts, "CN="+s.CommonName)
	}
	if s.Organization != "" {
		parts = append(parts, "O="+s.Organization)
	}
	if s.OrgUnit != "" {
		parts = append(parts, "OU="+s.OrgUnit)
	}
	if s.Country != "" {
		parts = append(parts, "C="+s.Country)
	}
	if s.Province != "" {
		parts = append(parts, "ST="+s.Province)
	}
	if s.Locality != "" {
		parts = append(parts, "L="+s.Locality)
	}
	fmt.Printf("  %-11s  %s\n", label+":", strings.Join(parts, ", "))
}
