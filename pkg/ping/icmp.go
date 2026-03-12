package ping

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func icmpPing(ctx context.Context, host string, seq int, timeout time.Duration) Result {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return Result{Seq: seq, Error: fmt.Sprintf("resolve: %v", err)}
	}
	dst := addrs[0]

	// Try unprivileged (udp4) first, fall back to privileged (ip4:icmp)
	conn, err := icmp.ListenPacket("udp4", "")
	network := "udp4"
	if err != nil {
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		network = "ip4"
		if err != nil {
			return Result{Seq: seq, Error: fmt.Sprintf("listen: %v (try running with sudo)", err)}
		}
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  seq,
			Data: []byte("NETCHK"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return Result{Seq: seq, Error: fmt.Sprintf("marshal: %v", err)}
	}

	var dstAddr net.Addr
	if network == "udp4" {
		dstAddr = &net.UDPAddr{IP: net.ParseIP(dst)}
	} else {
		dstAddr = &net.IPAddr{IP: net.ParseIP(dst)}
	}

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetDeadline(deadline)

	// Close connection when context is cancelled (e.g., user stops ping)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	id := os.Getpid() & 0xffff

	start := time.Now()
	if _, err := conn.WriteTo(wb, dstAddr); err != nil {
		return Result{Seq: seq, Error: fmt.Sprintf("write: %v", err)}
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return Result{Seq: seq, Addr: dst, Error: fmt.Sprintf("Request timeout for icmp_seq %d", seq)}
			}
			return Result{Seq: seq, Addr: dst, Error: fmt.Sprintf("read: %v", err)}
		}

		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}

		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := rm.Body.(*icmp.Echo)
		if !ok || echo.ID != id || echo.Seq != seq {
			continue
		}

		rtt := time.Since(start)
		addr := dst
		if peer != nil {
			addr = peer.String()
		}
		return Result{
			Seq:     seq,
			Success: true,
			RTT:     rtt,
			Addr:    addr,
			Bytes:   n,
		}
	}
}
