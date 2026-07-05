package k8s

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// parseGenerateKubeconfigAllString normalizes all to "true" or "false" for the API. Empty means true.
func parseGenerateKubeconfigAllString(s string) (parsed bool, norm string, err error) {
	trimmed := strings.TrimSpace(s)
	low := strings.ToLower(trimmed)
	if low == "" {
		return true, "true", nil
	}
	switch low {
	case "true":
		return true, "true", nil
	case "false":
		return false, "false", nil
	default:
		return false, "", fmt.Errorf("invalid all value %q; use true or false", trimmed)
	}
}

// ExtractInternalSessionID parses an ISP JWT without signature verification and
// returns the internal_session_id claim used to namespace SCA K8s session caches.
func ExtractInternalSessionID(jwtToken string) (string, error) {
	jwtToken = strings.TrimSpace(jwtToken)
	if jwtToken == "" {
		return "", fmt.Errorf("ExtractInternalSessionID: token is empty")
	}
	parsed, _, err := new(jwt.Parser).ParseUnverified(jwtToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("ExtractInternalSessionID: failed to parse token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("ExtractInternalSessionID: token claims are not a map")
	}
	raw, ok := claims["internal_session_id"]
	if !ok {
		return "", fmt.Errorf("ExtractInternalSessionID: internal_session_id claim is missing")
	}
	sid, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("ExtractInternalSessionID: internal_session_id claim is not a string (got %T)", raw)
	}
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return "", fmt.Errorf("ExtractInternalSessionID: internal_session_id claim is empty")
	}
	return sid, nil
}
