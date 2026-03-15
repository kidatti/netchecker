//go:build linux

package gateway

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Default returns the default gateway IP by parsing /proc/net/route.
// Returns "" on failure.
func Default() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Destination == 00000000 means default route
		if fields[1] == "00000000" {
			gw, err := hexToIP(fields[2])
			if err != nil {
				return ""
			}
			return gw
		}
	}
	return ""
}

// hexToIP converts a little-endian hex string (e.g. "0101A8C0") to dotted IP (e.g. "192.168.1.1").
func hexToIP(h string) (string, error) {
	if len(h) != 8 {
		return "", fmt.Errorf("invalid hex IP: %s", h)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	// /proc/net/route stores IPs in little-endian (host byte order on x86)
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]), nil
}
