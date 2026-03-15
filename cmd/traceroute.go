package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"netchecker/pkg/traceroute"
)

func RunTraceroute(args []string) {
	fs := flag.NewFlagSet("traceroute", flag.ExitOnError)
	maxHops := fs.Int("m", 30, "max number of hops")
	ipv4Flag := fs.Bool("4", false, "use IPv4 only")
	ipv6Flag := fs.Bool("6", false, "use IPv6 only")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: netchecker traceroute [-m maxhops] <host>\n")
		os.Exit(1)
	}
	host := fs.Arg(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		cancel()
	}()

	ipVersion := 0
	if *ipv4Flag {
		ipVersion = 4
	} else if *ipv6Flag {
		ipVersion = 6
	}

	err := traceroute.Run(ctx, host, traceroute.Options{MaxHops: *maxHops, IPVersion: ipVersion},
		func(dstIP string) {
			fmt.Printf("traceroute to %s (%s), %d hops max\n", host, dstIP, *maxHops)
		},
		func(h traceroute.Hop) {
			if h.Timeout {
				fmt.Printf("%2d  *\n", h.TTL)
			} else if h.Error != "" {
				fmt.Printf("%2d  error: %s\n", h.TTL, h.Error)
			} else {
				name := h.Host
				if name == h.Addr {
					name = ""
				}
				if name != "" {
					fmt.Printf("%2d  %s (%s)  %v\n", h.TTL, h.Host, h.Addr, h.RTT)
				} else {
					fmt.Printf("%2d  %s  %v\n", h.TTL, h.Addr, h.RTT)
				}
			}
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "traceroute: %v\n", err)
		os.Exit(1)
	}
}
