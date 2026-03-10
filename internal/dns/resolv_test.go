package dns

import (
	"strings"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single nameserver",
			input: "nameserver 8.8.8.8\n",
			want:  "8.8.8.8",
		},
		{
			name:  "multiple nameservers returns first",
			input: "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
			want:  "1.1.1.1",
		},
		{
			name:  "comment lines ignored",
			input: "# this is a comment\n; also a comment\nnameserver 9.9.9.9\n",
			want:  "9.9.9.9",
		},
		{
			name:  "empty file",
			input: "",
			want:  "",
		},
		{
			name:  "no nameserver entries",
			input: "search example.com\ndomain example.com\n",
			want:  "",
		},
		{
			name:  "nameserver with extra whitespace",
			input: "  nameserver   10.0.0.1  \n",
			want:  "10.0.0.1",
		},
		{
			name:  "nameserver line without address",
			input: "nameserver\nnameserver 8.8.4.4\n",
			want:  "8.8.4.4",
		},
		{
			name:  "mixed content",
			input: "# resolver config\nsearch local\nnameserver 192.168.1.1\noptions ndots:5\n",
			want:  "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseResolvConf(strings.NewReader(tt.input))
			if got != tt.want {
				t.Errorf("ParseResolvConf() = %q, want %q", got, tt.want)
			}
		})
	}
}
