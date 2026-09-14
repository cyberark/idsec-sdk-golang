package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/identity"
)

const (
	discoveryServiceDomainName = "platform-discovery"
	discoveryTimeout           = 30

	discoveryRetryAttempts = 3
	discoveryRetryDelay    = 1
	discoveryRetryMaxDelay = 4
	discoveryRetryBackoff  = 2
)

// DefaultHeaders returns the default headers for HTTP requests to identity.
func DefaultHeaders() map[string]string {
	return map[string]string{
		"Content-Type":         "application/json",
		"X-IDAP-NATIVE-CLIENT": "true",
		"User-Agent":           config.UserAgent(),
		"OobIdPAuth":           "true",
	}
}

// DefaultSystemHeaders returns the default system headers for HTTP requests to identity.
func DefaultSystemHeaders() map[string]string {
	return map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
		"User-Agent":           config.UserAgent(),
	}
}

// ResolveTenantFqdnFromTenantSubdomain resolves the tenant's FQDN URL from its subdomain.
// The resolved URL is based on the current working environment, which is provided in the `tenantSubdomain` argument.
//
// The call is retried up to discoveryRetryAttempts times with exponential backoff to handle
// transient failures (e.g. timeouts under concurrent load against the platform-discovery service).
func ResolveTenantFqdnFromTenantSubdomain(tenantSubdomain string, rootDomain string) (string, error) {
	client := common.NewSimpleIdsecClient(fmt.Sprintf("https://%s.%s", discoveryServiceDomainName, rootDomain))
	client.SetHeaders(map[string]string{
		"Content-Type": "application/json",
	})
	return resolveFqdnWithClient(tenantSubdomain, client)
}

// resolveFqdnWithClient performs the discovery call with retry, using the provided HTTP client.
// It is extracted to allow unit tests to supply a client that points at a local test server.
func resolveFqdnWithClient(tenantSubdomain string, client *common.IdsecClient) (string, error) {
	var fqdn string
	maxDelay := discoveryRetryMaxDelay

	err := common.RetryCall(
		func() error {
			ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout*time.Second)
			defer cancel()

			response, err := client.Get(ctx, fmt.Sprintf("api/identity-endpoint/%s", tenantSubdomain), nil)
			if err != nil {
				return fmt.Errorf("getting tenant FQDN failed from platform discovery: %v", err)
			}
			defer func(Body io.ReadCloser) {
				if closeErr := Body.Close(); closeErr != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)

			if response.StatusCode != http.StatusOK {
				return fmt.Errorf("getting tenant FQDN failed from platform discovery [%d] - [%s]", response.StatusCode, response.Status)
			}

			var parsedResponse identity.TenantEndpointResponse
			if err := json.NewDecoder(response.Body).Decode(&parsedResponse); err != nil {
				return fmt.Errorf("getting tenant FQDN failed from platform discovery to be parsed / validated")
			}
			fqdn = parsedResponse.Endpoint
			return nil
		},
		discoveryRetryAttempts,
		discoveryRetryDelay,
		&maxDelay,
		discoveryRetryBackoff,
		0,
		func(err error, delay int) {
			common.GlobalLogger.Warning("platform discovery FQDN resolution failed, retrying in %ds: %v", delay, err)
		},
	)
	if err != nil {
		return "", err
	}
	return fqdn, nil
}

// ResolveTenantFqdnFromTenantSuffix resolves the tenant's FQDN URL from its suffix.
func ResolveTenantFqdnFromTenantSuffix(tenantSuffix string, identityEnvURL string) (string, error) {
	if identityEnvURL == "" {
		awsEnvObject, _ := commonmodels.GetAwsEnvFromList()
		identityEnvURL = awsEnvObject.IdentityEnvURL
	}
	client := common.NewSimpleIdsecClient(fmt.Sprintf("https://pod0.%s", identityEnvURL))
	client.SetHeaders(map[string]string{
		"Content-Type":          "application/json",
		"X-IDAP-NATIVE-CLIENT'": "true",
	})
	body := map[string]interface{}{
		"User":                  tenantSuffix,
		"Version":               "1.0",
		"PlatformTokenResponse": true,
		"MfaRequestor":          "DeviceAgent",
	}
	response, err := client.Post(context.Background(), "Security/StartAuthentication", body)
	if err != nil {
		return "", err
	}
	if response.StatusCode == http.StatusOK {
		var parsedResponse identity.TenantFqdnResponse
		if err := json.NewDecoder(response.Body).Decode(&parsedResponse); err != nil {
			return "", fmt.Errorf("getting tenant FQDN failed from identity to be parsed / validated")
		}
		if !parsedResponse.Success || parsedResponse.Result.PodFqdn == "" {
			return "", fmt.Errorf("getting tenant FQDN failed from identity: %s", parsedResponse.Message)
		}
		fqdn := parsedResponse.Result.PodFqdn
		if !strings.HasPrefix(fqdn, "https://") {
			fqdn = "https://" + fqdn
		}
		return fqdn, nil
	}
	return "", fmt.Errorf("getting tenant FQDN failed from identity [%d] - [%s]", response.StatusCode, response.Status)
}
