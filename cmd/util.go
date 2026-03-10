package cmd

import "time"

func floatToDuration(secs float64) time.Duration {
	return time.Duration(secs * float64(time.Second))
}
