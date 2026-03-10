package tlscert

import (
	"crypto/tls"
	"math/big"
	"testing"
)

func TestFormatSerial(t *testing.T) {
	tests := []struct {
		name  string
		input *big.Int
		want  string
	}{
		{
			name:  "typical serial",
			input: big.NewInt(0x0102030405),
			want:  "01:02:03:04:05",
		},
		{
			name:  "single byte",
			input: big.NewInt(0xFF),
			want:  "FF",
		},
		{
			name:  "zero",
			input: big.NewInt(0),
			want:  "",
		},
		{
			name: "large serial",
			input: func() *big.Int {
				n, _ := new(big.Int).SetString("AABBCCDDEE00112233", 16)
				return n
			}(),
			want: "AA:BB:CC:DD:EE:00:11:22:33",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatSerial(tt.input)
			if got != tt.want {
				t.Errorf("formatSerial(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		name  string
		input uint16
		want  string
	}{
		{name: "TLS 1.0", input: tls.VersionTLS10, want: "TLS 1.0"},
		{name: "TLS 1.1", input: tls.VersionTLS11, want: "TLS 1.1"},
		{name: "TLS 1.2", input: tls.VersionTLS12, want: "TLS 1.2"},
		{name: "TLS 1.3", input: tls.VersionTLS13, want: "TLS 1.3"},
		{name: "unknown", input: 0x0200, want: "Unknown (0x0200)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tlsVersionString(tt.input)
			if got != tt.want {
				t.Errorf("tlsVersionString(0x%04X) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildSubjectInfo(t *testing.T) {
	tests := []struct {
		name     string
		cn       string
		org      []string
		ou       []string
		country  []string
		province []string
		locality []string
		want     SubjectInfo
	}{
		{
			name:     "all fields",
			cn:       "example.com",
			org:      []string{"Example Inc"},
			ou:       []string{"IT"},
			country:  []string{"US"},
			province: []string{"California"},
			locality: []string{"San Francisco"},
			want: SubjectInfo{
				CommonName:   "example.com",
				Organization: "Example Inc",
				OrgUnit:      "IT",
				Country:      "US",
				Province:     "California",
				Locality:     "San Francisco",
			},
		},
		{
			name: "empty fields",
			cn:   "",
			want: SubjectInfo{},
		},
		{
			name: "nil slices",
			cn:   "test.com",
			want: SubjectInfo{CommonName: "test.com"},
		},
		{
			name: "multiple orgs",
			cn:   "test.com",
			org:  []string{"Org1", "Org2"},
			want: SubjectInfo{
				CommonName:   "test.com",
				Organization: "Org1, Org2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSubjectInfo(tt.cn, tt.org, tt.ou, tt.country, tt.province, tt.locality)
			if got != tt.want {
				t.Errorf("buildSubjectInfo() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
