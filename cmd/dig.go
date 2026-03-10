package cmd

import (
	"flag"
	"fmt"
	"os"

	"netchecker/pkg/dig"
)

func RunDig(args []string) {
	fs := flag.NewFlagSet("dig", flag.ExitOnError)
	server := fs.String("server", "", "DNS server address")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: netchecker dig [-server addr] <domain> [A|AAAA|MX|NS|TXT|SOA|...]\n")
		os.Exit(1)
	}

	domain := fs.Arg(0)
	qtype := "A"
	if fs.NArg() >= 2 {
		qtype = fs.Arg(1)
	}

	result := dig.Query(domain, qtype, *server)

	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "dig: %s\n", result.Error)
		os.Exit(1)
	}

	fmt.Printf(";; ->>HEADER<<- rcode: %s, authoritative: %v\n", result.RCode, result.Authoritative)
	fmt.Printf(";; SERVER: %s\n", result.Server)
	fmt.Printf(";; QUERY: %s %s\n\n", result.Domain, result.QueryType)

	if len(result.Answer) > 0 {
		fmt.Println(";; ANSWER SECTION:")
		for _, r := range result.Answer {
			fmt.Printf("%-30s %d\tIN\t%s\t%s\n", r.Name, r.TTL, r.Type, r.Value)
		}
	}

	if len(result.Authority) > 0 {
		fmt.Println("\n;; AUTHORITY SECTION:")
		for _, r := range result.Authority {
			fmt.Printf("%-30s %d\tIN\t%s\t%s\n", r.Name, r.TTL, r.Type, r.Value)
		}
	}

	if len(result.Additional) > 0 {
		fmt.Println("\n;; ADDITIONAL SECTION:")
		for _, r := range result.Additional {
			fmt.Printf("%-30s %d\tIN\t%s\t%s\n", r.Name, r.TTL, r.Type, r.Value)
		}
	}

	fmt.Printf("\n;; Query time: %s\n", result.QueryTime)
}
