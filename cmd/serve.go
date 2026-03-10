package cmd

import (
	"flag"
	"fmt"
	"os"

	"netchecker/web"
)

func RunServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	fs.Parse(args)

	fmt.Printf("Starting netchecker web server on %s\n", *addr)
	if err := web.ListenAndServe(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}
