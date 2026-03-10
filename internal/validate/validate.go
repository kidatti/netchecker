package validate

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Domain validates a domain name or IP address.
// IP addresses are accepted as-is. Domain names must be ≤253 characters,
// each label ≤63 characters, and contain only [a-zA-Z0-9.-].
func Domain(s string) error {
	if s == "" {
		return fmt.Errorf("domain must not be empty")
	}

	// Allow valid IP addresses
	if net.ParseIP(s) != nil {
		return nil
	}

	if len(s) > 253 {
		return fmt.Errorf("domain must not exceed 253 characters")
	}

	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 {
			continue // trailing dot is acceptable
		}
		if len(label) > 63 {
			return fmt.Errorf("domain label %q exceeds 63 characters", label)
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return fmt.Errorf("domain contains invalid character: %q", c)
			}
		}
	}

	return nil
}

// Port validates a port number string. Must be a number between 1 and 65535.
func Port(s string) error {
	if s == "" {
		return fmt.Errorf("port must not be empty")
	}

	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("port must be a number")
	}

	if n < 1 || n > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	return nil
}
