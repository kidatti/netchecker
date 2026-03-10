package traceroute

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Hop struct {
	TTL     int           `json:"ttl"`
	Addr    string        `json:"addr,omitempty"`
	Host    string        `json:"host,omitempty"`
	RTT     time.Duration `json:"rtt"`
	Reached bool          `json:"reached"`
	Timeout bool          `json:"timeout"`
	Error   string        `json:"error,omitempty"`
}

type Options struct {
	MaxHops int
}

func Run(ctx context.Context, host string, opts Options, onResolved func(dstIP string), callback func(Hop)) error {
	if opts.MaxHops == 0 {
		opts.MaxHops = 30
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	dstIP := net.ParseIP(addrs[0])

	if onResolved != nil {
		onResolved(dstIP.String())
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("icmp listen: %w (try running with sudo)", err)
	}
	defer conn.Close()

	pconn := conn.IPv4PacketConn()

	for ttl := 1; ttl <= opts.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hop := probe(conn, pconn, dstIP, ttl)
		hop.TTL = ttl
		callback(hop)

		if hop.Reached {
			return nil
		}
	}
	return nil
}

func probe(conn *icmp.PacketConn, pconn *ipv4.PacketConn, dst net.IP, ttl int) Hop {
	id := os.Getpid() & 0xffff
	seq := ttl

	if err := pconn.SetTTL(ttl); err != nil {
		return Hop{Error: fmt.Sprintf("set ttl: %v", err)}
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("NETCHK-TR"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return Hop{Error: fmt.Sprintf("marshal: %v", err)}
	}

	deadline := time.Now().Add(3 * time.Second)
	conn.SetDeadline(deadline)

	start := time.Now()
	if _, err := conn.WriteTo(wb, &net.IPAddr{IP: dst}); err != nil {
		return Hop{Error: fmt.Sprintf("write: %v", err)}
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		rtt := time.Since(start)

		if err != nil {
			return Hop{Timeout: true}
		}

		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			// Verify this is our echo reply
			if echo, ok := rm.Body.(*icmp.Echo); ok {
				if echo.ID != id || echo.Seq != seq {
					continue
				}
			}
			peerIP := peer.String()
			return Hop{Addr: peerIP, Host: reverseLookup(peerIP), RTT: rtt, Reached: true}

		case ipv4.ICMPTypeTimeExceeded, ipv4.ICMPTypeDestinationUnreachable:
			// The body contains the original IP header + first 8 bytes of original ICMP
			// Parse to verify it's our probe
			if !matchOriginalProbe(rm, id, seq) {
				continue
			}
			peerIP := peer.String()
			reached := rm.Type == ipv4.ICMPTypeDestinationUnreachable
			return Hop{Addr: peerIP, Host: reverseLookup(peerIP), RTT: rtt, Reached: reached}
		}
		// Unknown type, keep reading
	}
}

// matchOriginalProbe checks if the Time Exceeded / Dest Unreachable body
// contains our original ICMP echo (matching ID and Seq).
func matchOriginalProbe(rm *icmp.Message, id, seq int) bool {
	body, ok := rm.Body.(*icmp.TimeExceeded)
	if !ok {
		body2, ok2 := rm.Body.(*icmp.DstUnreach)
		if !ok2 {
			return false
		}
		return extractAndMatch(body2.Data, id, seq)
	}
	return extractAndMatch(body.Data, id, seq)
}

// extractAndMatch parses the embedded original packet data.
// The data contains the original IP header (typically 20 bytes) followed
// by at least the first 8 bytes of the original ICMP message.
func extractAndMatch(data []byte, id, seq int) bool {
	if len(data) < 28 {
		return false
	}
	// IP header length from IHL field
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+8 {
		return false
	}
	icmpData := data[ihl:]
	// ICMP echo: type(1) code(1) checksum(2) id(2) seq(2)
	origID := int(icmpData[4])<<8 | int(icmpData[5])
	origSeq := int(icmpData[6])<<8 | int(icmpData[7])
	return origID == id && origSeq == seq
}

func reverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip
	}
	return strings.TrimRight(names[0], ".")
}
