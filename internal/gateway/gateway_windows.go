//go:build windows

package gateway

import (
	"os/exec"
	"strings"
)

// Default returns the default gateway IP by parsing "route print 0.0.0.0".
// Returns "" on failure.
func Default() string {
	out, err := exec.Command("cmd", "/c", "route", "print", "0.0.0.0").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return fields[2]
		}
	}
	return ""
}
