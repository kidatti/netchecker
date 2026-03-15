package ping

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func icmpPing(ctx context.Context, host string, seq int, timeout time.Duration, ipVersion int) Result {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return Result{Seq: seq, Error: fmt.Sprintf("resolve: %v", err)}
	}

	dst, isV6 := pickAddr(addrs, ipVersion)
	if dst == "" {
		v := ipVersion
		if v == 0 {
			v = 4
		}
		return Result{Seq: seq, Error: fmt.Sprintf("no IPv%d address found for %s", v, host)}
	}

	var conn *icmp.PacketConn
	var network string

	if isV6 {
		conn, err = icmp.ListenPacket("udp6", "")
		network = "udp6"
		if err != nil {
			conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
			network = "ip6"
			if err != nil {
				return Result{Seq: seq, Error: fmt.Sprintf("listen: %v (try running with sudo)", err)}
			}
		}
	} else {
		conn, err = icmp.ListenPacket("udp4", "")
		network = "udp4"
		if err != nil {
			conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
			network = "ip4"
			if err != nil {
				return Result{Seq: seq, Error: fmt.Sprintf("listen: %v (try running with sudo)", err)}
			}
		}
	}
	defer conn.Close()

	var msgType icmp.Type
	var replyType icmp.Type
	var protoNum int
	if isV6 {
		msgType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		protoNum = 58
	} else {
		msgType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
		protoNum = 1
	}

	id := os.Getpid() & 0xffff
	msg := icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("NETCHK"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return Result{Seq: seq, Error: fmt.Sprintf("marshal: %v", err)}
	}

	var dstAddr net.Addr
	switch network {
	case "udp4", "udp6":
		dstAddr = &net.UDPAddr{IP: net.ParseIP(dst)}
	default:
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

		rm, err := icmp.ParseMessage(protoNum, rb[:n])
		if err != nil {
			continue
		}

		if rm.Type != replyType {
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

// pickAddr selects an address from the resolved list based on ipVersion preference.
// Returns the selected address and whether it is IPv6.
func pickAddr(addrs []string, ipVersion int) (string, bool) {
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		isV4 := ip.To4() != nil
		switch ipVersion {
		case 4:
			if isV4 {
				return addr, false
			}
		case 6:
			if !isV4 {
				return addr, true
			}
		default:
			return addr, !isV4
		}
	}
	return "", false
}
