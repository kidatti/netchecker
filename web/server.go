package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"netchecker/internal/dns"
	"netchecker/internal/validate"
	"netchecker/pkg/dig"
	"netchecker/pkg/mailauth"
	"netchecker/pkg/nslookup"
	"netchecker/pkg/ping"
	"netchecker/pkg/tlscert"
	"netchecker/pkg/traceroute"
)

//go:embed static/*
var staticFiles embed.FS

func ListenAndServe(addr string) error {
	mux := http.NewServeMux()

	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	mux.HandleFunc("/api/netinfo", handleNetInfo)
	mux.HandleFunc("/api/ping/stream", handlePingStream)
	mux.HandleFunc("/api/traceroute/stream", handleTracerouteStream)
	mux.HandleFunc("/api/nslookup", handleNslookup)
	mux.HandleFunc("/api/dig", handleDig)
	mux.HandleFunc("/api/dig/all", handleDigAll)
	mux.HandleFunc("/api/mailauth", handleMailAuth)
	mux.HandleFunc("/api/tlscert", handleTLSCert)

	return http.ListenAndServe(addr, mux)
}

func handlePingStream(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	if err := validate.Domain(host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	icmpMode := r.URL.Query().Get("icmp") == "true"

	var timeout time.Duration
	if t := r.URL.Query().Get("timeout"); t != "" {
		if secs, err := strconv.ParseFloat(t, 64); err == nil && secs > 0 {
			timeout = time.Duration(secs * float64(time.Second))
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	opts := ping.Options{ICMP: icmpMode, Count: 0, Timeout: timeout}

	ping.Run(r.Context(), host, opts, func(result ping.Result) {
		data, _ := json.Marshal(result)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	})
	fmt.Fprintf(w, "event: done\ndata: {}\n\n")
	flusher.Flush()
}

func handleTracerouteStream(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	if err := validate.Domain(host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx := r.Context()

	err := traceroute.Run(ctx, host, traceroute.Options{},
		func(dstIP string) {
			infoData, _ := json.Marshal(map[string]string{"dst_ip": dstIP})
			fmt.Fprintf(w, "event: info\ndata: %s\n\n", infoData)
			flusher.Flush()
		},
		func(hop traceroute.Hop) {
			data, _ := json.Marshal(hop)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		})

	if err != nil {
		errData, _ := json.Marshal(map[string]string{"error": err.Error()})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", errData)
	}
	fmt.Fprintf(w, "event: done\ndata: {}\n\n")
	flusher.Flush()
}

func handleNslookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}
	if err := validate.Domain(req.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := nslookup.Lookup(r.Context(), req.Domain, req.Server)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleDig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}
	if err := validate.Domain(req.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		req.Type = "A"
	}

	result := dig.Query(req.Domain, req.Type, req.Server)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleDigAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}
	if err := validate.Domain(req.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	types := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR"}
	results := make(map[string]dig.Result, len(types))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range types {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			r := dig.Query(req.Domain, t, req.Server)
			mu.Lock()
			results[t] = r
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleMailAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
		Server string `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}
	if err := validate.Domain(req.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := mailauth.Check(req.Domain, req.Server)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleTLSCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Host string `json:"host"`
		Port string `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	if err := validate.Domain(req.Host); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Port == "" {
		req.Port = "443"
	}
	if err := validate.Port(req.Port); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := tlscert.Check(req.Host, req.Port)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleNetInfo(w http.ResponseWriter, r *http.Request) {
	type netInfoResponse struct {
		IPs       []string `json:"ips"`
		Hostname  string   `json:"hostname"`
		DNSServer string   `json:"dns_server"`
	}

	resp := netInfoResponse{}

	// Hostname
	resp.Hostname, _ = os.Hostname()

	// Collect non-loopback IPs
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && !ip.IsLoopback() {
					resp.IPs = append(resp.IPs, ip.String())
				}
			}
		}
	}

	// Parse /etc/resolv.conf for default DNS server
	resp.DNSServer = dns.DefaultServer()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

