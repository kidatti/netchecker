package dig

import (
	"fmt"
	"net"
	"strings"
	"time"

	"netchecker/internal/dns"

	"golang.org/x/net/dns/dnsmessage"
)

type Result struct {
	Domain        string   `json:"domain"`
	Server        string   `json:"server"`
	QueryType     string   `json:"query_type"`
	RCode         string   `json:"rcode"`
	Authoritative bool     `json:"authoritative"`
	Answer        []Record `json:"answer,omitempty"`
	Authority     []Record `json:"authority,omitempty"`
	Additional    []Record `json:"additional,omitempty"`
	QueryTime     string   `json:"query_time"`
	Error         string   `json:"error,omitempty"`
}

type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

var typeMap = map[string]dnsmessage.Type{
	"A":     dnsmessage.TypeA,
	"AAAA":  dnsmessage.TypeAAAA,
	"MX":    dnsmessage.TypeMX,
	"NS":    dnsmessage.TypeNS,
	"TXT":   dnsmessage.TypeTXT,
	"SOA":   dnsmessage.TypeSOA,
	"CNAME": dnsmessage.TypeCNAME,
	"PTR":   dnsmessage.TypePTR,
	"SRV":   dnsmessage.TypeSRV,
}

func Query(domain, qtype, server string) Result {
	if server == "" {
		server = dns.DefaultServer()
		if server == "" {
			server = "8.8.8.8"
		}
	}
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	dnsType, ok := typeMap[strings.ToUpper(qtype)]
	if !ok {
		return Result{Domain: domain, Error: fmt.Sprintf("unknown query type: %s", qtype)}
	}

	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		return Result{Domain: domain, Error: fmt.Sprintf("invalid domain: %v", err)}
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               0xABCD,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{Name: name, Type: dnsType, Class: dnsmessage.ClassINET},
		},
	}

	packed, err := msg.Pack()
	if err != nil {
		return Result{Domain: domain, Error: fmt.Sprintf("pack: %v", err)}
	}

	resp, queryTime, err := queryUDP(server, packed)
	if err != nil {
		return Result{Domain: domain, Error: err.Error()}
	}

	// TCP fallback if response was truncated
	if resp.Header.Truncated {
		resp, queryTime, err = queryTCP(server, packed)
		if err != nil {
			return Result{Domain: domain, Error: err.Error()}
		}
	}

	result := Result{
		Domain:        domain,
		Server:        server,
		QueryType:     strings.ToUpper(qtype),
		RCode:         resp.Header.RCode.String(),
		Authoritative: resp.Header.Authoritative,
		QueryTime:     queryTime.String(),
	}

	for _, r := range resp.Answers {
		result.Answer = append(result.Answer, resourceToRecord(r))
	}
	for _, r := range resp.Authorities {
		result.Authority = append(result.Authority, resourceToRecord(r))
	}
	for _, r := range resp.Additionals {
		result.Additional = append(result.Additional, resourceToRecord(r))
	}

	return result
}

func resourceToRecord(r dnsmessage.Resource) Record {
	rec := Record{
		Name: r.Header.Name.String(),
		TTL:  r.Header.TTL,
	}

	switch body := r.Body.(type) {
	case *dnsmessage.AResource:
		rec.Type = "A"
		rec.Value = net.IP(body.A[:]).String()
	case *dnsmessage.AAAAResource:
		rec.Type = "AAAA"
		rec.Value = net.IP(body.AAAA[:]).String()
	case *dnsmessage.MXResource:
		rec.Type = "MX"
		rec.Value = fmt.Sprintf("%d %s", body.Pref, body.MX.String())
	case *dnsmessage.NSResource:
		rec.Type = "NS"
		rec.Value = body.NS.String()
	case *dnsmessage.TXTResource:
		rec.Type = "TXT"
		rec.Value = strings.Join(body.TXT, " ")
	case *dnsmessage.SOAResource:
		rec.Type = "SOA"
		rec.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
			body.NS.String(), body.MBox.String(), body.Serial, body.Refresh, body.Retry, body.Expire, body.MinTTL)
	case *dnsmessage.CNAMEResource:
		rec.Type = "CNAME"
		rec.Value = body.CNAME.String()
	case *dnsmessage.PTRResource:
		rec.Type = "PTR"
		rec.Value = body.PTR.String()
	case *dnsmessage.SRVResource:
		rec.Type = "SRV"
		rec.Value = fmt.Sprintf("%d %d %d %s", body.Priority, body.Weight, body.Port, body.Target.String())
	default:
		rec.Type = fmt.Sprintf("TYPE%d", r.Header.Type)
		rec.Value = "(unparsed)"
	}
	return rec
}

func queryUDP(server string, packed []byte) (dnsmessage.Message, time.Duration, error) {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return dnsmessage.Message{}, 0, fmt.Errorf("connect: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	start := time.Now()
	if _, err := conn.Write(packed); err != nil {
		return dnsmessage.Message{}, 0, fmt.Errorf("write: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	elapsed := time.Since(start)
	if err != nil {
		return dnsmessage.Message{}, elapsed, fmt.Errorf("read: %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(buf[:n]); err != nil {
		return dnsmessage.Message{}, elapsed, fmt.Errorf("unpack: %v", err)
	}
	return msg, elapsed, nil
}

func queryTCP(server string, packed []byte) (dnsmessage.Message, time.Duration, error) {
	conn, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return dnsmessage.Message{}, 0, fmt.Errorf("tcp connect: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// TCP DNS: 2-byte length prefix
	length := uint16(len(packed))
	tcpBuf := make([]byte, 2+len(packed))
	tcpBuf[0] = byte(length >> 8)
	tcpBuf[1] = byte(length)
	copy(tcpBuf[2:], packed)

	start := time.Now()
	if _, err := conn.Write(tcpBuf); err != nil {
		return dnsmessage.Message{}, 0, fmt.Errorf("tcp write: %v", err)
	}

	// Read 2-byte length
	lenBuf := make([]byte, 2)
	if _, err := conn.Read(lenBuf); err != nil {
		return dnsmessage.Message{}, 0, fmt.Errorf("tcp read length: %v", err)
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	respBuf := make([]byte, respLen)
	total := 0
	for total < respLen {
		n, err := conn.Read(respBuf[total:])
		if err != nil {
			return dnsmessage.Message{}, 0, fmt.Errorf("tcp read: %v", err)
		}
		total += n
	}
	elapsed := time.Since(start)

	var msg dnsmessage.Message
	if err := msg.Unpack(respBuf); err != nil {
		return dnsmessage.Message{}, elapsed, fmt.Errorf("tcp unpack: %v", err)
	}
	return msg, elapsed, nil
}

