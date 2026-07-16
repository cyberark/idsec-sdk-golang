package k8s

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const awsIDCPermissionSetARNMarker = "arn:aws:sso:::permissionSet/"

// IsAWSIDCPermissionSetRole reports whether roleID is an AWS IAM Identity Center permission set ARN.
func IsAWSIDCPermissionSetRole(roleID string) bool {
	return strings.Contains(strings.TrimSpace(roleID), awsIDCPermissionSetARNMarker)
}

// NeedsAWSIDCDeviceRegistration reports whether the elevate result requires the
// AWS IDC device-authorization flow before STS credentials can be obtained.
func NeedsAWSIDCDeviceRegistration(result *k8smodels.IdsecSCAK8sElevateResult) bool {
	if result == nil || !IsAWSIDCPermissionSetRole(result.RoleID) {
		return false
	}
	cd := result.ClientDetails
	if cd == nil {
		return false
	}
	return strings.TrimSpace(cd.ClientID) != "" &&
		strings.TrimSpace(cd.ClientSecret) != "" &&
		strings.TrimSpace(cd.StartURL) != "" &&
		strings.TrimSpace(awsIDCRegion(cd)) != ""
}

func awsIDCRegion(cd *k8smodels.IdsecSCAK8sElevateClientDetails) string {
	if cd == nil {
		return ""
	}
	return strings.TrimSpace(cd.SSORegion)
}

// ValidateAWSIDCDeviceRegistration validates the Elevate payload required for
// AWS IDC permission-set authentication. Non-permission-set role IDs are not
// validated here and return nil.
func ValidateAWSIDCDeviceRegistration(result *k8smodels.IdsecSCAK8sElevateResult) error {
	if result == nil {
		return fmt.Errorf("elevate result cannot be nil")
	}
	if !IsAWSIDCPermissionSetRole(result.RoleID) {
		return nil
	}

	var missing []string
	if strings.TrimSpace(result.WorkspaceID) == "" {
		missing = append(missing, "workspaceId")
	}
	if strings.TrimSpace(result.RoleName) == "" {
		missing = append(missing, "roleName")
	}
	if result.ClientDetails == nil {
		missing = append(missing, "clientDetails")
	} else {
		if strings.TrimSpace(result.ClientDetails.ClientID) == "" {
			missing = append(missing, "clientDetails.clientId")
		}
		if strings.TrimSpace(result.ClientDetails.ClientSecret) == "" {
			missing = append(missing, "clientDetails.clientSecret")
		}
		if strings.TrimSpace(result.ClientDetails.StartURL) == "" {
			missing = append(missing, "clientDetails.startUrl")
		}
		if strings.TrimSpace(awsIDCRegion(result.ClientDetails)) == "" {
			missing = append(missing, "clientDetails.ssoRegion")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"AWS IDC permission-set flow requires complete elevate fields; missing: %s",
			strings.Join(missing, ", "),
		)
	}
	return nil
}

// MarshalAWSAccessCredentials serializes AWS STS credentials into the JSON string
// format expected by the Elevate accessCredentials field.
func MarshalAWSAccessCredentials(creds *k8smodels.IdsecSCAK8sAWSAccessCredentials) (string, error) {
	if creds == nil {
		return "", fmt.Errorf("AWS access credentials cannot be nil")
	}
	payload, err := json.Marshal(creds)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AWS access credentials: %w", err)
	}
	return string(payload), nil
}

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

// ParseNamespaceName returns the namespace value from a --namespace input, which may be
// a bare name or an Azure resource ID containing a "/namespaces/<value>" segment.
// When the marker is present, everything after "/namespaces/" is returned as-is.
func ParseNamespaceName(namespaceID string) string {
	trimmed := strings.TrimSpace(namespaceID)
	if trimmed == "" {
		return ""
	}
	const marker = "/namespaces/"
	idx := strings.LastIndex(trimmed, marker)
	if idx == -1 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[idx+len(marker):])
}

// ISPSessionClaims holds the JWT claims used by SCA K8s caches.
// The token is parsed without signature verification; trust boundary is the local machine.
type ISPSessionClaims struct {
	SessionID string // internal_session_id — rotates the cache namespace on full re-auth
	UserUUID  string // user_uuid — stable per-user identity for cache isolation
}

// ExtractISPSessionClaims parses the ISP JWT once and returns both cache-key claims.
// Returns an error only if the token cannot be parsed at all. Missing or non-string
// individual claims are returned as empty strings; callers disable caches when empty.
func ExtractISPSessionClaims(jwtToken string) (ISPSessionClaims, error) {
	jwtToken = strings.TrimSpace(jwtToken)
	if jwtToken == "" {
		return ISPSessionClaims{}, fmt.Errorf("ExtractISPSessionClaims: token is empty")
	}
	parsed, _, err := new(jwt.Parser).ParseUnverified(jwtToken, jwt.MapClaims{})
	if err != nil {
		return ISPSessionClaims{}, fmt.Errorf("ExtractISPSessionClaims: failed to parse token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return ISPSessionClaims{}, fmt.Errorf("ExtractISPSessionClaims: token claims are not a map")
	}
	var result ISPSessionClaims
	if v, ok := claims["internal_session_id"].(string); ok {
		result.SessionID = strings.TrimSpace(v)
	}
	if v, ok := claims["user_uuid"].(string); ok {
		result.UserUUID = strings.TrimSpace(v)
	}
	return result, nil
}
