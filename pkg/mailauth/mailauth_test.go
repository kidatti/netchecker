package mailauth

import (
	"testing"
)

func TestParseSPF(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "standard SPF record",
			raw:  "v=spf1 include:_spf.google.com ~all",
			want: map[string]string{
				"version":    "spf1",
				"mechanisms": "include:_spf.google.com ~all",
			},
		},
		{
			name: "SPF with redirect",
			raw:  "v=spf1 redirect=_spf.example.com",
			want: map[string]string{
				"version":  "spf1",
				"redirect": "_spf.example.com",
			},
		},
		{
			name: "mechanisms only",
			raw:  "v=spf1 +mx +a -all",
			want: map[string]string{
				"version":    "spf1",
				"mechanisms": "+mx +a -all",
			},
		},
		{
			name: "version only",
			raw:  "v=spf1",
			want: map[string]string{
				"version": "spf1",
			},
		},
		{
			name: "empty string",
			raw:  "",
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSPF(tt.raw)
			if len(got) != len(tt.want) {
				t.Errorf("parseSPF(%q) returned %d keys, want %d", tt.raw, len(got), len(tt.want))
				t.Errorf("  got:  %v", got)
				t.Errorf("  want: %v", tt.want)
				return
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("parseSPF(%q)[%q] = %q, want %q", tt.raw, k, got[k], v)
				}
			}
		})
	}
}

func TestParseTags(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "DMARC tags",
			raw:  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
			want: map[string]string{
				"v":   "DMARC1",
				"p":   "reject",
				"rua": "mailto:dmarc@example.com",
			},
		},
		{
			name: "BIMI tags",
			raw:  "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem",
			want: map[string]string{
				"v": "BIMI1",
				"l": "https://example.com/logo.svg",
				"a": "https://example.com/cert.pem",
			},
		},
		{
			name: "empty string",
			raw:  "",
			want: map[string]string{},
		},
		{
			name: "semicolon only",
			raw:  ";",
			want: map[string]string{},
		},
		{
			name: "tag without equals",
			raw:  "v=DMARC1; noequals; p=none",
			want: map[string]string{
				"v":        "DMARC1",
				"noequals": "",
				"p":        "none",
			},
		},
		{
			name: "whitespace around values",
			raw:  "v = DMARC1 ; p = reject",
			want: map[string]string{
				"v": "DMARC1",
				"p": "reject",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTags(tt.raw)
			if len(got) != len(tt.want) {
				t.Errorf("parseTags(%q) returned %d keys, want %d", tt.raw, len(got), len(tt.want))
				t.Errorf("  got:  %v", got)
				t.Errorf("  want: %v", tt.want)
				return
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("parseTags(%q)[%q] = %q, want %q", tt.raw, k, got[k], v)
				}
			}
		})
	}
}
