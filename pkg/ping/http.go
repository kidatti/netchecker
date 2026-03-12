package ping

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func httpPing(ctx context.Context, url string, seq int, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return Result{Seq: seq, Error: fmt.Sprintf("%v", err)}
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	start := time.Now()
	resp, err := client.Do(req)
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
