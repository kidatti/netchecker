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
	"golang.org/x/net/ipv6"
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
	MaxHops   int
	IPVersion int // 0=auto, 4=IPv4, 6=IPv6
}

func Run(ctx context.Context, host string, opts Options, onResolved func(dstIP string), callback func(Hop)) error {
	if opts.MaxHops == 0 {
		opts.MaxHops = 30
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}

	dst, isV6 := pickAddr(addrs, opts.IPVersion)
	if dst == nil {
		v := opts.IPVersion
		if v == 0 {
			v = 4
		}
		return fmt.Errorf("no IPv%d address found for %s", v, host)
	}

	if onResolved != nil {
		onResolved(dst.String())
	}

	var conn *icmp.PacketConn
	if isV6 {
		conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
	} else {
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	}
	if err != nil {
		return fmt.Errorf("icmp listen: %w (try running with sudo)", err)
	}
	defer conn.Close()

	for ttl := 1; ttl <= opts.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hop := probe(conn, dst, ttl, isV6)
		hop.TTL = ttl
		callback(hop)

		if hop.Reached {
			return nil
		}
	}
	return nil
}

func probe(conn *icmp.PacketConn, dst net.IP, ttl int, isV6 bool) Hop {
	id := os.Getpid() & 0xffff
	seq := ttl

	if isV6 {
		if err := conn.IPv6PacketConn().SetHopLimit(ttl); err != nil {
			return Hop{Error: fmt.Sprintf("set hop limit: %v", err)}
		}
	} else {
		if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
			return Hop{Error: fmt.Sprintf("set ttl: %v", err)}
		}
	}

	var msgType icmp.Type
	var protoNum int
	if isV6 {
		msgType = ipv6.ICMPTypeEchoRequest
		protoNum = 58
	} else {
		msgType = ipv4.ICMPTypeEcho
		protoNum = 1
	}

	msg := icmp.Message{
		Type: msgType,
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

	var echoReplyType, timeExceededType, dstUnreachType icmp.Type
	if isV6 {
		echoReplyType = ipv6.ICMPTypeEchoReply
		timeExceededType = ipv6.ICMPTypeTimeExceeded
		dstUnreachType = ipv6.ICMPTypeDestinationUnreachable
	} else {
		echoReplyType = ipv4.ICMPTypeEchoReply
		timeExceededType = ipv4.ICMPTypeTimeExceeded
		dstUnreachType = ipv4.ICMPTypeDestinationUnreachable
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		rtt := time.Since(start)

		if err != nil {
			return Hop{Timeout: true}
		}

		rm, err := icmp.ParseMessage(protoNum, buf[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case echoReplyType:
			if echo, ok := rm.Body.(*icmp.Echo); ok {
				if echo.ID != id || echo.Seq != seq {
					continue
				}
			}
			peerIP := peer.String()
			return Hop{Addr: peerIP, Host: reverseLookup(peerIP), RTT: rtt, Reached: true}

		case timeExceededType, dstUnreachType:
			if !matchOriginalProbe(rm, id, seq, isV6) {
				continue
			}
			peerIP := peer.String()
			reached := rm.Type == dstUnreachType
			return Hop{Addr: peerIP, Host: reverseLookup(peerIP), RTT: rtt, Reached: reached}
		}
	}
}

// matchOriginalProbe checks if the Time Exceeded / Dest Unreachable body
// contains our original ICMP echo (matching ID and Seq).
func matchOriginalProbe(rm *icmp.Message, id, seq int, isV6 bool) bool {
	body, ok := rm.Body.(*icmp.TimeExceeded)
	if !ok {
		body2, ok2 := rm.Body.(*icmp.DstUnreach)
		if !ok2 {
			return false
		}
		return extractAndMatch(body2.Data, id, seq, isV6)
	}
	return extractAndMatch(body.Data, id, seq, isV6)
}

// extractAndMatch parses the embedded original packet data.
// For IPv4: data contains the original IP header (variable length via IHL) + first 8 bytes of ICMP.
// For IPv6: data contains the original IPv6 header (40 bytes) + first 8 bytes of ICMPv6.
func extractAndMatch(data []byte, id, seq int, isV6 bool) bool {
	var hdrLen int
	if isV6 {
		hdrLen = 40
	} else {
		if len(data) < 20 {
			return false
		}
		hdrLen = int(data[0]&0x0f) * 4
	}
	if len(data) < hdrLen+8 {
		return false
	}
	icmpData := data[hdrLen:]
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

// pickAddr selects an address from the resolved list based on ipVersion preference.
func pickAddr(addrs []string, ipVersion int) (net.IP, bool) {
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		isV4 := ip.To4() != nil
		switch ipVersion {
		case 4:
			if isV4 {
				return ip, false
			}
		case 6:
			if !isV4 {
				return ip, true
			}
		default:
			return ip, !isV4
		}
	}
	return nil, false
}
