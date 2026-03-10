package dns

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// ParseResolvConf reads nameserver entries from an io.Reader in resolv.conf format
// and returns the first nameserver address found. Returns "" if none found.
func ParseResolvConf(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return ""
}

// DefaultServer returns the first nameserver from /etc/resolv.conf.
// Returns "" if the file cannot be read or contains no nameserver entries.
func DefaultServer() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer f.Close()
	return ParseResolvConf(f)
}
