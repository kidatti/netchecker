package main

import (
	"fmt"
	"os"

	"netchecker/cmd"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	args := os.Args[2:]

	switch subcommand {
	case "ping":
		cmd.RunPing(args)
	case "traceroute":
		cmd.RunTraceroute(args)
	case "nslookup":
		cmd.RunNslookup(args)
	case "dig":
		cmd.RunDig(args)
	case "tlscert":
		cmd.RunTLSCert(args)
	case "serve":
		cmd.RunServe(args)
	case "version":
		fmt.Printf("netchecker version %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", subcommand)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: netchecker <command> [options]

Commands:
  ping        HTTP/ICMP ping
  traceroute  Trace route to host
  nslookup    DNS lookup
  dig         DNS query (detailed)
  tlscert     TLS certificate check
  serve       Start web interface
  version     Show version
`)
}
