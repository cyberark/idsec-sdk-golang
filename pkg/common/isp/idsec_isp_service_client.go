// Package isp provides ISP (Identity Service Provider) client functionality for the IDSEC SDK.
//
// This package contains the IdsecISPServiceClient which handles authentication and service
// URL resolution for ISP-based services. It provides functionality to create clients,
// resolve service URLs based on tenant information, and manage JWT token-based authentication
// with cookie support.
package isp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// IdsecISPServiceClient is a struct that represents a client for the Idsec ISP service.
//
// This client extends the common IdsecClient with ISP-specific functionality including
// tenant environment management and JWT token parsing for service URL resolution.
// It handles authentication headers, cookies, and maintains connection state for
// ISP-based services.
type IdsecISPServiceClient struct {
	*common.IdsecClient
	tenantEnv commonmodels.AwsEnv
}

// NewIdsecISPServiceClient creates a new instance of IdsecISPServiceClient.
//
// This function initializes a new ISP service client with the provided configuration.
// It resolves the service URL based on the tenant information and JWT token, sets up
// the underlying IdsecClient with appropriate headers, and configures authentication.
// If tenantEnv is empty, it attempts to resolve it from environment variables or
// defaults to production.
//
// Parameters:
//   - serviceName: The name of the service to connect to (e.g., "api", "portal")
//   - tenantSubdomain: The tenant subdomain to use for URL construction
//   - baseTenantURL: The base tenant URL to use if subdomain resolution fails
//   - tenantEnv: The AWS environment (dev, staging, prod) - uses DEPLOY_ENV if empty
//   - token: The JWT authentication token for the service
//   - authHeaderName: The name of the authorization header (typically "Authorization")
//   - separator: The separator character used between tenant and service name in URLs
//   - basePath: Additional base path to append to the service URL
//   - cookieJar: The cookie jar for maintaining session state
//   - refreshConnectionCallback: Callback function to refresh the connection when needed
//
// Returns a configured IdsecISPServiceClient instance and any error that occurred during
// initialization, particularly from URL parsing or service URL resolution.
//
// Example:
//
//	client, err := NewIdsecISPServiceClient(
//	    "api",
//	    "mytenant",
//	    "https://mytenant.cyberark.cloud",
//	    commonmodels.Prod,
//	    jwtToken,
//	    "Authorization",
//	    "-",
//	    "v1",
//	    cookieJar,
//	    refreshCallback,
//	)
func NewIdsecISPServiceClient(
	serviceName string,
	tenantSubdomain string,
	baseTenantURL string,
	tenantEnv commonmodels.AwsEnv,
	token string,
	authHeaderName string,
	separator string,
	basePath string,
	cookieJar *cookiejar.Jar,
	refreshConnectionCallback func(*common.IdsecClient) error,
) (*IdsecISPServiceClient, error) {
	if tenantEnv == "" {
		tenantEnv = commonmodels.AwsEnv(os.Getenv("DEPLOY_ENV"))
		if tenantEnv == "" {
			tenantEnv = commonmodels.Prod
		}
	}

	serviceURL, err := resolveServiceURL(serviceName, tenantSubdomain, baseTenantURL, tenantEnv, token, separator)
	if err != nil {
		return nil, err
	}
	if basePath != "" {
		serviceURL = fmt.Sprintf("%s/%s", serviceURL, basePath)
	}
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service URL: %w", err)
	}
	client := common.NewIdsecClient(serviceURL, token, "Bearer", authHeaderName, cookieJar, refreshConnectionCallback, serviceName, true)
	client.SetHeader("Origin", fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host))
	client.SetHeader("Referer", fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host))
	client.SetHeader("Content-Type", "application/json")
	client.SetHeader("Accept", "*/*")
	client.SetHeader("Connection", "keep-alive")

	return &IdsecISPServiceClient{
		IdsecClient: client,
		tenantEnv:   tenantEnv,
	}, nil
}

// resolveServiceURL resolves the complete service URL based on tenant and service information.
//
// This internal function constructs the full service URL by analyzing the JWT token,
// extracting tenant subdomain information, and resolving the appropriate platform domain.
// It supports multiple methods of subdomain resolution: from JWT token claims, explicit
// subdomain parameter, base tenant URL parsing, and unique_name claim extraction.
//
// Parameters:
//   - serviceName: The name of the service to connect to
//   - tenantSubdomain: Explicit tenant subdomain (used if JWT parsing fails)
//   - baseTenantURL: Base tenant URL for subdomain extraction as fallback
//   - tenantEnv: The AWS environment, resolved from token or environment if empty
//   - token: JWT token containing tenant and platform information
//   - separator: Separator character for URL construction between tenant and service
//
// Returns the resolved service URL string and any error that occurred during JWT parsing
// or URL construction. Returns an error if tenant subdomain cannot be resolved through
// any available method.
func resolveServiceURL(
	serviceName string,
	tenantSubdomain string,
	baseTenantURL string,
	tenantEnv commonmodels.AwsEnv,
	token string,
	separator string,
) (string, error) {
	awsEnvObject, _ := commonmodels.GetAwsEnvFromList()
	platformDomain := awsEnvObject.RootDomain
	var tenantChosenSubdomain string

	if token != "" {
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			return "", err
		}
		claims := parsedToken.Claims.(jwt.MapClaims)
		if subdomain, ok := claims["subdomain"].(string); ok {
			tenantChosenSubdomain = subdomain
		}
		if platformTokenDomain, ok := claims["platform_domain"].(string); ok {
			platformDomain = platformTokenDomain
			if strings.HasPrefix(platformDomain, "shell.") && serviceName != "" {
				platformDomain = strings.TrimPrefix(platformDomain, "shell.")
			}
			for _, domain := range commonmodels.AwsEnvList {
				if domain.RootDomain == platformDomain {
					break
				}
			}
		}
	}

	if tenantChosenSubdomain == "" && tenantSubdomain != "" {
		tenantChosenSubdomain = tenantSubdomain
	}

	if tenantChosenSubdomain == "" && baseTenantURL != "" {
		if !strings.HasPrefix(baseTenantURL, "https://") {
			baseTenantURL = "https://" + baseTenantURL
		}
		parsedURL, err := url.Parse(baseTenantURL)
		if err != nil {
			return "", err
		}
		tenantChosenSubdomain = strings.Split(parsedURL.Host, ".")[0]
	}

	if tenantChosenSubdomain == "" && token != "" {
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			return "", err
		}
		claims := parsedToken.Claims.(jwt.MapClaims)
		if uniqueName, ok := claims["unique_name"].(string); ok {
			fullDomain := strings.Split(uniqueName, "@")
			if len(fullDomain) > 1 {
				domainPart := fullDomain[1]
				for _, domain := range commonmodels.AwsEnvList {
					if strings.Contains(domainPart, domain.RootDomain) {
						tenantChosenSubdomain = strings.Split(domainPart, ".")[0]
						platformDomain = domain.RootDomain
						break
					}
				}
			}
		}
	}

	if tenantChosenSubdomain == "" {
		return "", fmt.Errorf("failed to resolve tenant subdomain")
	}

	var baseURL string
	if serviceName != "" {
		baseURL = fmt.Sprintf("https://%s%s%s.%s", tenantChosenSubdomain, separator, serviceName, platformDomain)
	} else {
		baseURL = fmt.Sprintf("https://%s.%s", tenantChosenSubdomain, platformDomain)
	}

	return baseURL, nil
}

// TenantEnv returns the tenant environment of the IdsecISPServiceClient.
//
// This method provides access to the AWS environment (dev, staging, prod) that was
// resolved during client initialization. The environment is determined from the JWT
// token, explicit parameter, or environment variables during client creation.
//
// Returns the commonmodels.AwsEnv value representing the current tenant environment.
//
// Example:
//
//	env := client.TenantEnv()
//	if env == commonmodels.Prod {
//	    // Handle production environment logic
//	}
func (client *IdsecISPServiceClient) TenantEnv() commonmodels.AwsEnv {
	return client.tenantEnv
}

// TenantID returns the tenant ID from the JWT token of the IdsecISPServiceClient.
//
// This method extracts the tenant ID from the JWT token claims stored in the client.
// It parses the token without verification to access the tenant_id claim. The method
// requires a valid JWT token to be present in the client.
//
// Returns the tenant ID as a string and any error that occurred during JWT token
// parsing. Returns an error if no token is available or if the token cannot be parsed.
// Note: This method performs type assertion on the tenant_id claim and may panic if
// the claim is not a string type.
//
// Example:
//
//	tenantID, err := client.TenantID()
//	if err != nil {
//	    log.Printf("Failed to get tenant ID: %v", err)
//	    return
//	}
//	fmt.Printf("Current tenant: %s", tenantID)
func (client *IdsecISPServiceClient) TenantID() (string, error) {
	if client.GetToken() != "" {
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(client.GetToken(), jwt.MapClaims{})
		if err != nil {
			return "", err
		}
		claims := parsedToken.Claims.(jwt.MapClaims)
		return claims["tenant_id"].(string), nil
	}
	return "", fmt.Errorf("failed to retrieve tenant id")
}

// FromISPAuth creates a new IdsecISPServiceClient from an IdsecISPAuth instance.
//
// This function creates an ISP service client using authentication information from
// an existing IdsecISPAuth instance. It extracts tenant environment information from
// the auth token's username or metadata, decodes and sets up cookies from the token
// metadata, and initializes the client with the appropriate configuration.
//
// Parameters:
//   - ispAuth: The IdsecISPAuth instance containing authentication information and tokens
//   - serviceName: The name of the service to connect to
//   - separator: The separator character used in URL construction
//   - basePath: Additional base path to append to the service URL
//   - refreshConnectionCallback: Callback function for connection refresh operations
//
// Returns a configured IdsecISPServiceClient and any error that occurred during client
// creation, cookie unmarshaling, or service URL resolution.
//
// Example:
//
//	client, err := FromISPAuth(
//	    ispAuth,
//	    "api",
//	    "-",
//	    "v1",
//	    refreshCallback,
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to create client: %w", err)
//	}
func FromISPAuth(ispAuth *auth.IdsecISPAuth, serviceName string, separator string, basePath string, refreshConnectionCallback func(*common.IdsecClient) error) (*IdsecISPServiceClient, error) {
	var tenantEnv commonmodels.AwsEnv
	var baseTenantURL string
	if ispAuth.Token.Username != "" {
		for _, domain := range commonmodels.AwsEnvList {
			if strings.Contains(ispAuth.Token.Username, domain.RootDomain) && strings.Contains(ispAuth.Token.Username, "@") {
				baseTenantURL = strings.Split(ispAuth.Token.Username, "@")[1]
				tenantEnv = domain.AwsEnv
				break
			}
		}
	}
	if tenantEnv == "" && ispAuth.Token.Metadata["env"] != "" {
		tenantEnv = commonmodels.AwsEnv(ispAuth.Token.Metadata["env"].(string))
	}
	if tenantEnv == "" {
		tenantEnv = commonmodels.AwsEnv(os.Getenv("DEPLOY_ENV"))
		if tenantEnv == "" {
			tenantEnv = commonmodels.Prod
		}
	}
	cookieJar, _ := cookiejar.New(nil)
	if cookies, ok := ispAuth.Token.Metadata["cookies"]; ok {
		decoded, _ := base64.StdEncoding.DecodeString(cookies.(string))
		err := common.UnmarshalCookies(decoded, cookieJar)
		if err != nil {
			return nil, err
		}
	}
	return NewIdsecISPServiceClient(serviceName, "", baseTenantURL, tenantEnv, ispAuth.Token.Token, "Authorization", separator, basePath, cookieJar, refreshConnectionCallback)
}

// RefreshClient refreshes the IdsecISPServiceClient with the latest authentication token and cookies.
//
// This function updates an existing IdsecClient with fresh authentication credentials
// by loading the latest authentication token from the provided IdsecISPAuth instance.
// It updates both the authentication token and any associated cookies stored in the
// token metadata. The cookies are base64 decoded and applied to the client.
//
// Parameters:
//   - client: The IdsecClient instance to refresh with new credentials
//   - ispAuth: The IdsecISPAuth instance to load fresh authentication from
//
// Returns any error that occurred during authentication loading, token updating,
// or cookie processing. The function performs forced authentication refresh by
// passing true as the refresh parameter to LoadAuthentication.
//
// Example:
//
//	err := RefreshClient(client.IdsecClient, ispAuth)
//	if err != nil {
//	    return fmt.Errorf("failed to refresh client: %w", err)
//	}
func RefreshClient(client *common.IdsecClient, ispAuth *auth.IdsecISPAuth) error {
	token, err := ispAuth.LoadAuthentication(ispAuth.ActiveProfile, true)
	if err != nil {
		return err
	}
	if token != nil {
		client.UpdateToken(token.Token, client.GetTokenType())
		cookieJar := make(map[string]string)
		if cookies, ok := token.Metadata["cookies"]; ok {
			decoded, _ := base64.StdEncoding.DecodeString(cookies.(string))
			_ = json.Unmarshal(decoded, &cookieJar)
		}
		client.UpdateCookies(cookieJar)
	}
	return nil
}
