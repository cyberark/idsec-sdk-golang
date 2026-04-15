package services

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
)

// IdsecISPBaseService provides base ISP authentication and client management functionality.
// This mid-level base service should be embedded by all services that use ISP authentication,
// eliminating the need for each service to manage its own ispAuth and client fields.
// It implements the telemetry methods required by the IdsecService interface.
//
// Services embed this to automatically get ISP client creation and telemetry support.
type IdsecISPBaseService struct {
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecISPBaseService creates a new instance of IdsecISPBaseService with an initialized ISP client.
//
// This constructor handles all ISP client creation boilerplate, allowing services to simply
// embed the base service without managing client creation themselves.
//
// Parameters:
//   - ispAuth: The ISP authenticator instance
//   - serviceName: The service name for ISP client initialization (e.g., "dpa", "privilegecloud", "connectormanagement")
//   - version: The version string for ISP client (typically ".")
//   - apiVersion: The API version path (e.g., "", "passwordvault", "api/idadmin")
//   - refreshFunc: Callback function to refresh the client connection
//
// Returns the initialized IdsecISPBaseService or an error if client creation fails.
//
// Example:
//
//	ispBaseService, err := services.NewIdsecISPBaseService(
//		ispAuth,
//		"privilegecloud",
//		".",
//		"passwordvault",
//		service.refreshPCloudAuth,
//	)
//	if err != nil {
//		return nil, err
//	}
func NewIdsecISPBaseService(
	ispAuth *auth.IdsecISPAuth,
	serviceName string,
	version string,
	apiVersion string,
	refreshFunc func(*common.IdsecClient) error,
) (*IdsecISPBaseService, error) {
	// Create the ISP client with service-specific parameters
	client, err := isp.FromISPAuth(ispAuth, serviceName, version, apiVersion, refreshFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ISP client for service '%s': %w", serviceName, err)
	}

	return &IdsecISPBaseService{
		ispAuth: ispAuth,
		client:  client,
	}, nil
}

// NewIdsecISPBaseServiceWithRetry creates a new instance of IdsecISPBaseService with an initialized ISP client.
//
// This constructor handles all ISP client creation boilerplate, allowing services to simply
// embed the base service without managing client creation themselves.
//
// Parameters:
//   - ispAuth: The ISP authenticator instance
//   - serviceName: The service name for ISP client initialization (e.g., "dpa", "privilegecloud", "connectormanagement")
//   - version: The version string for ISP client (typically ".")
//   - apiVersion: The API version path (e.g., "", "passwordvault", "api/idadmin")
//   - refreshFunc: Callback function to refresh the client connection
//
// Returns the initialized IdsecISPBaseService or an error if client creation fails.
//
// Example:
//
//	ispBaseService, err := services.NewIdsecISPBaseServiceWithRetry(
//		ispAuth,
//		"privilegecloud",
//		".",
//		"passwordvault",
//		service.refreshPCloudAuth,
//		retryStrategy,
//	)
//	if err != nil {
//		return nil, err
//	}
func NewIdsecISPBaseServiceWithRetry(
	ispAuth *auth.IdsecISPAuth,
	serviceName string,
	version string,
	apiVersion string,
	refreshFunc func(*common.IdsecClient) error,
	retryStrategy common.IdsecClientRetryStrategy,
) (*IdsecISPBaseService, error) {
	// Create the ISP client with service-specific parameters
	client, err := isp.FromISPAuth(ispAuth, serviceName, version, apiVersion, refreshFunc, retryStrategy)
	if err != nil {
		return nil, fmt.Errorf("failed to create ISP client for service '%s': %w", serviceName, err)
	}

	return &IdsecISPBaseService{
		ispAuth: ispAuth,
		client:  client,
	}, nil
}

// ISPAuth returns the ISP authenticator for this service.
func (s *IdsecISPBaseService) ISPAuth() *auth.IdsecISPAuth {
	return s.ispAuth
}

// ISPClient returns the ISP client for this service.
// This is exposed for special cases like calling UpdateHeaders or other client-specific methods.
func (s *IdsecISPBaseService) ISPClient() *isp.IdsecISPServiceClient {
	return s.client
}

// AddExtraContextField adds a custom context field to telemetry data.
// This method implements the IdsecService interface's telemetry requirement.
// Returns an error if the ISP client is not initialized.
func (s *IdsecISPBaseService) AddExtraContextField(name, shortName, value string) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("ISP client not initialized")
	}
	s.client.AddExtraContextField(name, shortName, value)
	return nil
}

// ClearExtraContext removes all extra context fields from telemetry data.
// This method implements the IdsecService interface's telemetry requirement.
// Returns an error if the ISP client is not initialized.
func (s *IdsecISPBaseService) ClearExtraContext() error {
	if s == nil || s.client == nil {
		return fmt.Errorf("ISP client not initialized")
	}
	s.client.ClearExtraContext()
	return nil
}
