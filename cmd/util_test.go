package cmd

import (
	"testing"
	"time"
)

func TestFloatToDuration(t *testing.T) {
	tests := []struct {
		name  string
		input float64
		want  time.Duration
	}{
		{name: "zero", input: 0, want: 0},
		{name: "one second", input: 1.0, want: time.Second},
		{name: "half second", input: 0.5, want: 500 * time.Millisecond},
		{name: "negative", input: -1.0, want: -time.Second},
		{name: "fractional", input: 2.5, want: 2500 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := floatToDuration(tt.input)
			if got != tt.want {
				t.Errorf("floatToDuration(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
