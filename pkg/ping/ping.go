package ping

import (
	"context"
	"math"
	"time"
)

type Result struct {
	Seq        int           `json:"seq"`
	Success    bool          `json:"success"`
	StatusCode int           `json:"status_code,omitempty"`
	RTT        time.Duration `json:"rtt"`
	Error      string        `json:"error,omitempty"`
	Addr       string        `json:"addr,omitempty"`
	Bytes      int           `json:"bytes,omitempty"`
}

type Stats struct {
	Sent     int           `json:"sent"`
	Received int           `json:"received"`
	Loss     float64       `json:"loss"`
	MinRTT   time.Duration `json:"min_rtt"`
	AvgRTT   time.Duration `json:"avg_rtt"`
	MaxRTT   time.Duration `json:"max_rtt"`
}

type Options struct {
	ICMP     bool
	Count    int
	Interval time.Duration
	Timeout  time.Duration
}

func Run(ctx context.Context, host string, opts Options, callback func(Result)) Stats {
	if opts.Interval == 0 {
		opts.Interval = time.Second
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}

	var stats Stats
	var totalRTT time.Duration
	minRTT := time.Duration(math.MaxInt64)
	var maxRTT time.Duration

	doOne := func(seq int) {
		var r Result
		if opts.ICMP {
			r = icmpPing(host, seq, opts.Timeout)
		} else {
			r = httpPing(host, seq, opts.Timeout)
		}
		stats.Sent++
		if r.Success {
			stats.Received++
			totalRTT += r.RTT
			if r.RTT < minRTT {
				minRTT = r.RTT
			}
			if r.RTT > maxRTT {
				maxRTT = r.RTT
			}
		}
		callback(r)
	}

	seq := 0
	doOne(seq)
	seq++

	if opts.Count > 0 && seq >= opts.Count {
		return finalizeStats(stats, totalRTT, minRTT, maxRTT)
	}

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return finalizeStats(stats, totalRTT, minRTT, maxRTT)
		case <-ticker.C:
			doOne(seq)
			seq++
			if opts.Count > 0 && seq >= opts.Count {
				return finalizeStats(stats, totalRTT, minRTT, maxRTT)
			}
		}
	}
}

func finalizeStats(stats Stats, totalRTT, minRTT, maxRTT time.Duration) Stats {
	if stats.Sent > 0 {
		stats.Loss = float64(stats.Sent-stats.Received) / float64(stats.Sent) * 100
	}
	if stats.Received > 0 {
		stats.MinRTT = minRTT
		stats.MaxRTT = maxRTT
		stats.AvgRTT = totalRTT / time.Duration(stats.Received)
	}
	return stats
}
