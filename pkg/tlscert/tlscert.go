package tlscert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

type Result struct {
	Host            string     `json:"host"`
	Port            string     `json:"port"`
	TLSVersion      string     `json:"tls_version"`
	CipherSuite     string     `json:"cipher_suite"`
	Valid           bool       `json:"valid"`
	ValidationError string     `json:"validation_error,omitempty"`
	Certificates    []CertInfo `json:"certificates"`
	CheckTime       string     `json:"check_time"`
	Error           string     `json:"error,omitempty"`
}

type SubjectInfo struct {
	CommonName   string `json:"cn,omitempty"`
	Organization string `json:"org,omitempty"`
	OrgUnit      string `json:"ou,omitempty"`
	Country      string `json:"country,omitempty"`
	Province     string `json:"province,omitempty"`
	Locality     string `json:"locality,omitempty"`
}

type SANs struct {
	DNS   []string `json:"dns,omitempty"`
	IPs   []string `json:"ips,omitempty"`
	Email []string `json:"email,omitempty"`
	URIs  []string `json:"uris,omitempty"`
}

type CertInfo struct {
	Subject            SubjectInfo `json:"subject"`
	Issuer             SubjectInfo `json:"issuer"`
	SerialNumber       string      `json:"serial_number"`
	NotBefore          string      `json:"not_before"`
	NotAfter           string      `json:"not_after"`
	DaysUntilExpiry    int         `json:"days_until_expiry"`
	ExpiryWarning      string      `json:"expiry_warning,omitempty"`
	SANs               SANs        `json:"sans"`
	SignatureAlgorithm string      `json:"signature_algorithm"`
	PublicKeyAlgorithm string      `json:"public_key_algorithm"`
	PublicKeySize      int         `json:"public_key_size"`
	IsCA               bool        `json:"is_ca"`
	Version            int         `json:"version"`
}

func Check(host, port string) Result {
	start := time.Now()

	addr := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return Result{
			Host:      host,
			Port:      port,
			Error:     err.Error(),
			CheckTime: time.Since(start).String(),
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()

	result := Result{
		Host:        host,
		Port:        port,
		TLSVersion:  tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	// Verify certificates manually
	if len(state.PeerCertificates) > 0 {
		opts := x509.VerifyOptions{
			DNSName:       host,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, verifyErr := state.PeerCertificates[0].Verify(opts)
		if verifyErr != nil {
			result.Valid = false
			result.ValidationError = verifyErr.Error()
		} else {
			result.Valid = true
		}
	}

	for _, cert := range state.PeerCertificates {
		result.Certificates = append(result.Certificates, buildCertInfo(cert))
	}

	result.CheckTime = time.Since(start).String()
	return result
}

func buildCertInfo(cert *x509.Certificate) CertInfo {
	now := time.Now()
	daysUntil := int(cert.NotAfter.Sub(now).Hours() / 24)

	var warning string
	if now.After(cert.NotAfter) {
		warning = "EXPIRED"
	} else if daysUntil <= 30 {
		warning = "Expiring soon"
	}

	var sans SANs
	for _, name := range cert.DNSNames {
		sans.DNS = append(sans.DNS, name)
	}
	for _, ip := range cert.IPAddresses {
		sans.IPs = append(sans.IPs, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans.Email = append(sans.Email, email)
	}
	for _, uri := range cert.URIs {
		sans.URIs = append(sans.URIs, uri.String())
	}

	return CertInfo{
		Subject:            buildSubjectInfo(cert.Subject.CommonName, cert.Subject.Organization, cert.Subject.OrganizationalUnit, cert.Subject.Country, cert.Subject.Province, cert.Subject.Locality),
		Issuer:             buildSubjectInfo(cert.Issuer.CommonName, cert.Issuer.Organization, cert.Issuer.OrganizationalUnit, cert.Issuer.Country, cert.Issuer.Province, cert.Issuer.Locality),
		SerialNumber:       formatSerial(cert.SerialNumber),
		NotBefore:          cert.NotBefore.Format(time.RFC3339),
		NotAfter:           cert.NotAfter.Format(time.RFC3339),
		DaysUntilExpiry:    daysUntil,
		ExpiryWarning:      warning,
		SANs:               sans,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeySize:      publicKeySize(cert),
		IsCA:               cert.IsCA,
		Version:            cert.Version,
	}
}

func buildSubjectInfo(cn string, org, ou, country, province, locality []string) SubjectInfo {
	return SubjectInfo{
		CommonName:   cn,
		Organization: strings.Join(org, ", "),
		OrgUnit:      strings.Join(ou, ", "),
		Country:      strings.Join(country, ", "),
		Province:     strings.Join(province, ", "),
		Locality:     strings.Join(locality, ", "),
	}
}

func formatSerial(n *big.Int) string {
	b := n.Bytes()
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

func publicKeySize(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", v)
	}
}
