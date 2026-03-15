//go:build darwin

package gateway

import (
	"os/exec"
	"strings"
)

// Default returns the default gateway IP by parsing "route -n get default".
// Returns "" on failure.
func Default() string {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	return ""
}
