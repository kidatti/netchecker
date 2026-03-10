package validate

import (
	"strings"
	"testing"
)

func TestDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{name: "valid domain", input: "example.com", wantErr: false},
		{name: "valid subdomain", input: "sub.example.com", wantErr: false},
		{name: "valid IPv4", input: "192.168.1.1", wantErr: false},
		{name: "valid IPv6", input: "::1", wantErr: false},
		{name: "valid IPv6 full", input: "2001:db8::1", wantErr: false},
		{name: "domain with hyphen", input: "my-site.example.com", wantErr: false},
		{name: "single label", input: "localhost", wantErr: false},
		{name: "empty", input: "", wantErr: true, errMsg: "must not be empty"},
		{name: "too long", input: strings.Repeat("a", 254), wantErr: true, errMsg: "253 characters"},
		{name: "label too long", input: strings.Repeat("a", 64) + ".com", wantErr: true, errMsg: "63 characters"},
		{name: "invalid character underscore", input: "foo_bar.com", wantErr: true, errMsg: "invalid character"},
		{name: "invalid character space", input: "foo bar.com", wantErr: true, errMsg: "invalid character"},
		{name: "trailing dot accepted", input: "example.com.", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Domain(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Domain(%q) = nil, want error containing %q", tt.input, tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Domain(%q) error = %q, want error containing %q", tt.input, err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Domain(%q) = %v, want nil", tt.input, err)
				}
			}
		})
	}
}

func TestPort(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{name: "valid 443", input: "443", wantErr: false},
		{name: "valid 1", input: "1", wantErr: false},
		{name: "valid 65535", input: "65535", wantErr: false},
		{name: "valid 80", input: "80", wantErr: false},
		{name: "zero", input: "0", wantErr: true, errMsg: "between 1 and 65535"},
		{name: "too large", input: "65536", wantErr: true, errMsg: "between 1 and 65535"},
		{name: "negative", input: "-1", wantErr: true, errMsg: "between 1 and 65535"},
		{name: "not a number", input: "abc", wantErr: true, errMsg: "must be a number"},
		{name: "empty", input: "", wantErr: true, errMsg: "must not be empty"},
		{name: "float", input: "443.5", wantErr: true, errMsg: "must be a number"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Port(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Port(%q) = nil, want error containing %q", tt.input, tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Port(%q) error = %q, want error containing %q", tt.input, err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Port(%q) = %v, want nil", tt.input, err)
				}
			}
		})
	}
}
