package cmd

import (
	"context"
	"fmt"
	"os"

	"netchecker/pkg/nslookup"
)

func RunNslookup(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: netchecker nslookup <domain>\n")
		os.Exit(1)
	}
	domain := args[0]

	result := nslookup.Lookup(context.Background(), domain, "")

	fmt.Printf("Server:  default\n")
	fmt.Printf("Domain:  %s\n\n", result.Domain)

	if len(result.Addrs) > 0 {
		fmt.Println("Addresses:")
		for _, addr := range result.Addrs {
			fmt.Printf("  %s\n", addr)
		}
	}

	if result.CNAME != "" {
		fmt.Printf("\nCNAME:  %s\n", result.CNAME)
	}

	if len(result.MX) > 0 {
		fmt.Println("\nMX Records:")
		for _, mx := range result.MX {
			fmt.Printf("  %s (priority %d)\n", mx.Host, mx.Pref)
		}
	}

	if len(result.NS) > 0 {
		fmt.Println("\nName Servers:")
		for _, ns := range result.NS {
			fmt.Printf("  %s\n", ns)
		}
	}

	if len(result.TXT) > 0 {
		fmt.Println("\nTXT Records:")
		for _, txt := range result.TXT {
			fmt.Printf("  %s\n", txt)
		}
	}

	fmt.Printf("\nQuery time: %s\n", result.Time)
}
