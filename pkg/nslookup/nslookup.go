package nslookup

import (
	"context"
	"net"
	"time"
)

type Result struct {
	Domain string   `json:"domain"`
	Addrs  []string `json:"addrs,omitempty"`
	CNAME  string   `json:"cname,omitempty"`
	MX     []MXInfo `json:"mx,omitempty"`
	NS     []string `json:"ns,omitempty"`
	TXT    []string `json:"txt,omitempty"`
	Error  string   `json:"error,omitempty"`
	Time   string   `json:"time"`
}

type MXInfo struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

func Lookup(ctx context.Context, domain string, server string) Result {
	r := &net.Resolver{}
	if server != "" {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, server)
			},
		}
	}
	start := time.Now()
	result := Result{Domain: domain}

	addrs, err := r.LookupHost(ctx, domain)
	if err == nil {
		result.Addrs = addrs
	}

	cname, err := r.LookupCNAME(ctx, domain)
	if err == nil && cname != domain+"." {
		result.CNAME = cname
	}

	mxs, err := r.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxs {
			result.MX = append(result.MX, MXInfo{Host: mx.Host, Pref: mx.Pref})
		}
	}

	nss, err := r.LookupNS(ctx, domain)
	if err == nil {
		for _, ns := range nss {
			result.NS = append(result.NS, ns.Host)
		}
	}

	txts, err := r.LookupTXT(ctx, domain)
	if err == nil {
		result.TXT = txts
	}

	result.Time = time.Since(start).String()
	return result
}
