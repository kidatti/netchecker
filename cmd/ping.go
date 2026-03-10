package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"netchecker/pkg/ping"
)

func RunPing(args []string) {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	httpFlag := fs.Bool("http", false, "use HTTP instead of ICMP")
	count := fs.Int("c", 0, "number of pings (0 = infinite)")
	interval := fs.Float64("i", 1.0, "interval in seconds")
	timeout := fs.Float64("t", 5.0, "timeout in seconds")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: netchecker ping [--http] [-c count] [-i interval] [-t timeout] <host>\n")
		os.Exit(1)
	}
	host := fs.Arg(0)

	opts := ping.Options{
		ICMP:  !*httpFlag,
		Count: *count,
	}
	if *interval > 0 {
		opts.Interval = floatToDuration(*interval)
	}
	if *timeout > 0 {
		opts.Timeout = floatToDuration(*timeout)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	mode := "HTTP"
	if opts.ICMP {
		mode = "ICMP"
	}
	fmt.Printf("PING %s (%s)\n", host, mode)

	go func() {
		<-sig
		cancel()
	}()

	stats := ping.Run(ctx, host, opts, func(r ping.Result) {
		if r.Success {
			if opts.ICMP {
				fmt.Printf("seq=%d: bytes=%d addr=%s time=%v\n", r.Seq, r.Bytes, r.Addr, r.RTT)
			} else {
				fmt.Printf("seq=%d: status=%d time=%v\n", r.Seq, r.StatusCode, r.RTT)
			}
		} else {
			fmt.Printf("seq=%d: error - %s\n", r.Seq, r.Error)
		}
	})

	fmt.Printf("\n--- %s netchecker statistics ---\n", host)
	fmt.Printf("%d sent, %d received, %.1f%% loss\n", stats.Sent, stats.Received, stats.Loss)
	if stats.Received > 0 {
		fmt.Printf("rtt min/avg/max = %v/%v/%v\n", stats.MinRTT, stats.AvgRTT, stats.MaxRTT)
	}
}
