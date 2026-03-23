package common

import (
	"fmt"
	"net/url"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
)

const (
	ForcePlatformURLEnvVar = "IDSEC_IDENTITY_FORCE_PLATFORM_URL"
)

// ResolveIdentityServiceURL resolves the identity service URL from the ISP token claims. It falls back to the platform URL if the environment variable is set.
// This is used to set the base URL for the identity service client to avoid issues with certain API calls that require the identity service URL, especially for long-running API calls that may cause timeouts on the shell cloudfront side.
// Parameters:
//   - ispAuth: The ISP authenticator instance containing the token
//   - platformURL: The platform URL to use as a fallback if the environment variable is set
//
// Returns the resolved identity service URL or an error if parsing fails.
// Example usage:
//
//	identityServiceURL, err := ResolveIdentityServiceURL(ispAuth, platformURL)
//	if err != nil {
//		return nil, fmt.Errorf("failed to resolve identity service URL: %w", err)
//	}
func ResolveIdentityServiceURL(ispAuth *auth.IdsecISPAuth, platformURL string) (string, error) {
	// Set the base URL to the identity service endpoint instead of platform to avoid issues with certain API calls that require the identity service URL
	// This is also for API's which take long and cause timeout on the shell cloudfront side
	if platformURL != "" && (os.Getenv(ForcePlatformURLEnvVar) == "true" || ispAuth.Token.Token == "") {
		return platformURL, nil
	}
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(ispAuth.Token.Token, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims := parsedToken.Claims.(jwt.MapClaims)
	if claims["iss"] == nil {
		return "", fmt.Errorf("failed to parse issuer from token claims")
	}
	issuer := claims["iss"].(string)
	parsedURL, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("failed to parse issuer URL: %v", err)
	}
	return fmt.Sprintf("https://%s", parsedURL.Host), nil
}
