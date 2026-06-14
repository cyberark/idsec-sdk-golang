// Package pvwa provides PVWA (Password Vault Web Access) client functionality for the IDSEC SDK.
//
// This package builds PVWA REST clients from IdsecPVWAAuth using the session token from Logon
// as a raw Authorization header value (no Bearer prefix), matching CyberArk PVWA REST conventions.
package pvwa

import (
	"fmt"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	pvwaauth "github.com/cyberark/idsec-sdk-golang/pkg/auth/pvwa"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// IdsecPVWAServiceClient represents a client for CyberArk PVWA REST on the vault host.
//
// It embeds common.IdsecClient with PVWA session token authorization (raw Authorization header,
// no Bearer prefix). Product services typically obtain instances via FromPVWAAuth.
type IdsecPVWAServiceClient struct {
	*common.IdsecClient
}

// NewIdsecPVWAServiceClient creates a PVWA REST client for the given endpoint and session token.
//
// Parameters:
//   - endpoint: PVWA base URL from the authenticated token
//   - sessionToken: PVWA Logon session token
//   - serviceName: Owning SDK service name for telemetry/logging
//   - retryStrategy: Optional retry configuration; nil skips retry setup
//
// Returns the configured IdsecPVWAServiceClient or an error if client creation fails.
func NewIdsecPVWAServiceClient(
	endpoint string,
	sessionToken string,
	serviceName string,
	retryStrategy common.IdsecClientRetryStrategy,
) (*IdsecPVWAServiceClient, error) {
	endpoint = strings.TrimSpace(endpoint)
	client := common.NewIdsecClient(
		endpoint,
		sessionToken,
		common.IdsecAuthorizationTokenTypeRaw,
		"Authorization",
		nil,
		nil,
		serviceName,
		false,
	)
	if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		client.BaseURL = strings.TrimSuffix(endpoint, "/")
	}
	client.SetHeader("Content-Type", "application/json")
	if retryStrategy != nil {
		retryStrategy.ConfigureClient(client)
	}
	return &IdsecPVWAServiceClient{IdsecClient: client}, nil
}

// FromPVWAAuth builds an IdsecPVWAServiceClient from an authenticated IdsecPVWAAuth instance.
//
// Parameters:
//   - pvwaAuth: Authenticator with a non-nil Token
//   - serviceName: Owning SDK service name
//   - retryStrategy: Optional retry configuration; nil skips retry setup
//
// Returns the configured client or an error if the token is missing.
func FromPVWAAuth(
	pvwaAuth *auth.IdsecPVWAAuth,
	serviceName string,
	retryStrategy common.IdsecClientRetryStrategy,
) (*IdsecPVWAServiceClient, error) {
	if pvwaAuth == nil || pvwaAuth.Token == nil {
		return nil, fmt.Errorf("PVWA: missing auth or token")
	}
	tok := pvwaAuth.Token
	return NewIdsecPVWAServiceClient(
		tok.Endpoint,
		tok.Token,
		serviceName,
		retryStrategy,
	)
}

// ApplyTokenToClient sets the PVWA session token on client (raw Authorization header).
func ApplyTokenToClient(client *common.IdsecClient, sessionToken string) {
	pvwaauth.ApplyPVWASessionToClient(client, sessionToken)
}
