package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
)

func TestClassifySentinels(t *testing.T) {
	if r, ok := Classify(fmt.Errorf("wrapped: %w", ErrMFARequired)); !ok || r != ReasonMFARequired {
		t.Errorf("wrapped ErrMFARequired = (%q, %v), want (MFA_REQUIRED, true)", r, ok)
	}
	if r, ok := Classify(fmt.Errorf("%w: keyring locked", ErrKeyringFailure)); !ok || r != ReasonKeyringFailure {
		t.Errorf("wrapped ErrKeyringFailure = (%q, %v), want (KEYRING_FAILURE, true)", r, ok)
	}
}

func TestClassifyCertificateErrors(t *testing.T) {
	cases := map[string]error{
		"unknown authority": x509.UnknownAuthorityError{},
		"hostname":          x509.HostnameError{Host: "example.com"},
		"invalid":           x509.CertificateInvalidError{},
		"tls wrapped in url": &url.Error{
			Op:  "Get",
			URL: "https://example.com",
			Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
		},
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if r, ok := Classify(err); !ok || r != ReasonCertificateError {
				t.Errorf("Classify(%v) = (%q, %v), want (CERTIFICATE_ERROR, true)", err, r, ok)
			}
		})
	}
}

func TestClassifyNetworkErrors(t *testing.T) {
	cases := map[string]error{
		"deadline":  context.DeadlineExceeded,
		"op error":  &net.OpError{Op: "dial", Err: errors.New("connection refused")},
		"dns error": &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true},
		"url error": &url.Error{Op: "Get", URL: "https://example.com", Err: errors.New("connection refused")},
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if r, ok := Classify(err); !ok || r != ReasonEndpointUnreachable {
				t.Errorf("Classify(%v) = (%q, %v), want (ENDPOINT_UNREACHABLE, true)", err, r, ok)
			}
		})
	}
}

func TestClassifyCertificateBeatsNetwork(t *testing.T) {
	// A certificate failure surfaces as a *url.Error too; certificate must win.
	err := &url.Error{
		Op:  "Get",
		URL: "https://example.com",
		Err: &tls.CertificateVerificationError{Err: x509.HostnameError{Host: "example.com"}},
	}
	if r, ok := Classify(err); !ok || r != ReasonCertificateError {
		t.Errorf("Classify(cert-in-url) = (%q, %v), want (CERTIFICATE_ERROR, true)", r, ok)
	}
}

func TestClassifyUnknownAndNil(t *testing.T) {
	if r, ok := Classify(nil); ok || r != "" {
		t.Errorf("Classify(nil) = (%q, %v), want (\"\", false)", r, ok)
	}
	if r, ok := Classify(errors.New("something unexpected")); ok || r != "" {
		t.Errorf("Classify(unknown) = (%q, %v), want (\"\", false)", r, ok)
	}
}
