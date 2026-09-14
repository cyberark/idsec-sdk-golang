package common

// This file provides stable, machine-readable classification of authentication
// failures.
//
// It exists so that callers (for example a CLI) can react to a failure by a
// stable reason code rather than by matching against human-readable error
// text, which silently rots whenever an underlying message is reworded.
//
// Classification is type- and sentinel-based, never substring-based:
//
//   - Failures that only the authentication code can recognize (multi-factor
//     authentication required, token cache/keyring failures) are wrapped at
//     their source with the ErrMFARequired / ErrKeyringFailure sentinels.
//   - Transport failures (TLS/certificate problems, unreachable endpoints) are
//     recognized from the standard library error types (crypto/x509, crypto/tls,
//     net, net/url), which are stable across message wording.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
)

// Reason is a stable, machine-readable identifier for a class of authentication
// failure. Its string values are part of the public contract consumers rely on.
type Reason string

const (
	// ReasonMFARequired indicates multi-factor authentication is required and
	// could not be completed (for example in a non-interactive/silent login).
	ReasonMFARequired Reason = "MFA_REQUIRED"
	// ReasonEndpointUnreachable indicates the authentication endpoint could not
	// be reached (DNS failure, connection refused, timeout, etc.).
	ReasonEndpointUnreachable Reason = "ENDPOINT_UNREACHABLE"
	// ReasonKeyringFailure indicates the token cache (keyring) could not be read
	// from or written to.
	ReasonKeyringFailure Reason = "KEYRING_FAILURE"
	// ReasonCertificateError indicates a TLS/certificate verification problem
	// while contacting the authentication endpoint.
	ReasonCertificateError Reason = "CERTIFICATE_ERROR"
)

// ErrMFARequired is wrapped (with %w) at the points where authentication cannot
// proceed because multi-factor authentication needs interaction that is not
// available. Callers detect it via errors.Is or Classify.
var ErrMFARequired = errors.New("multi-factor authentication is required and cannot be completed non-interactively")

// ErrKeyringFailure is wrapped (with %w) around token cache/keyring read/write
// failures. Callers detect it via errors.Is or Classify.
var ErrKeyringFailure = errors.New("token cache (keyring) operation failed")

// Classify returns a stable Reason for an authentication error, and whether one
// was recognized. Sentinel-wrapped reasons take precedence over transport
// classification; a certificate problem takes precedence over a generic
// unreachable-endpoint classification.
func Classify(err error) (Reason, bool) {
	if err == nil {
		return "", false
	}
	switch {
	case errors.Is(err, ErrMFARequired):
		return ReasonMFARequired, true
	case errors.Is(err, ErrKeyringFailure):
		return ReasonKeyringFailure, true
	}
	if isCertificateError(err) {
		return ReasonCertificateError, true
	}
	if isNetworkError(err) {
		return ReasonEndpointUnreachable, true
	}
	return "", false
}

// isCertificateError reports whether err (or anything it wraps) is a TLS or
// x509 certificate verification failure.
func isCertificateError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	var tlsVerifyErr *tls.CertificateVerificationError
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &certInvalid) ||
		errors.As(err, &tlsVerifyErr)
}

// isNetworkError reports whether err (or anything it wraps) indicates the
// endpoint could not be reached: a timeout, a socket-level failure, a DNS
// failure, or a transport-level URL error.
func isNetworkError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}
