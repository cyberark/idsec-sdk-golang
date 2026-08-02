package common

import (
	"fmt"
	"strings"
)

// The SCA input-validation messages below are user-facing CLI text that the CLI
// surfaces verbatim (as "Error: <message>"). They intentionally start with a
// capital letter and end with punctuation, which is why staticcheck's ST1005 is
// suppressed here — centralizing them means the suppression lives in one place
// instead of being repeated at every call site.

// ErrUnsupportedCSP reports that the given CSP is not among the supported
// providers, e.g. "Unsupported CSP 'GCP'. Supported providers are: AWS, AZURE".
func ErrUnsupportedCSP(csp string, supported ...string) error {
	return fmt.Errorf("Unsupported CSP '%s'. Supported providers are: %s", csp, strings.Join(supported, ", ")) //nolint:staticcheck // user-facing CLI message wording
}

// ErrCSPEmpty reports that a required CSP value was empty, e.g.
// "The CSP cannot be empty. Supported providers are: AWS, AZURE".
func ErrCSPEmpty(supported ...string) error {
	return fmt.Errorf("The CSP cannot be empty. Supported providers are: %s", strings.Join(supported, ", ")) //nolint:staticcheck // user-facing CLI message wording
}

// ErrCSPAllConflict reports that --csp and --all were combined incorrectly.
func ErrCSPAllConflict() error {
	return fmt.Errorf("When using '--csp', '--all' can only be 'false', or should not be used at all.") //nolint:staticcheck // user-facing CLI message wording
}

// IsSupportedCSP reports whether csp matches one of the supported providers,
// case-insensitively.
func IsSupportedCSP(csp string, supported ...string) bool {
	for _, s := range supported {
		if strings.EqualFold(strings.TrimSpace(csp), s) {
			return true
		}
	}
	return false
}
