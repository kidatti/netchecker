package ping

import (
	"fmt"
	"net/http"
	"time"
)

func httpPing(url string, seq int, timeout time.Duration) Result {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	start := time.Now()
	resp, err := client.Get(url)
	rtt := time.Since(start)

	if err != nil {
		return Result{
			Seq:   seq,
			Error: fmt.Sprintf("%v", err),
		}
	}
	resp.Body.Close()

	return Result{
		Seq:        seq,
		Success:    true,
		StatusCode: resp.StatusCode,
		RTT:        rtt,
	}
}
