package services

import (
	"fmt"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	pvwaclient "github.com/cyberark/idsec-sdk-golang/pkg/common/pvwa"
)

// IdsecPVWABaseService provides base PVWA authentication and client management functionality.
// This mid-level base service should be embedded by all services that use PVWA authentication,
// eliminating the need for each service to manage its own pvwaAuth and client fields.
//
// The embedding service supplies a serviceName when constructing the base (see NewIdsecPVWABaseService).
// That name is passed to the underlying HTTP client as owningService (same role as serviceName on
// NewIdsecISPBaseService for ISP-backed services).
type IdsecPVWABaseService struct {
	pvwaAuth *auth.IdsecPVWAAuth
	client   *pvwaclient.IdsecPVWAServiceClient
}

func validatePVWAServiceName(serviceName string) error {
	if strings.TrimSpace(serviceName) == "" {
		return fmt.Errorf("PVWA: serviceName is required")
	}
	return nil
}

// NewIdsecPVWABaseServiceWithRESTOptions builds a PVWA base service for REST calls on the PVWA host.
//
// Parameters:
//   - pvwaAuth: The PVWA authenticator instance (must already be authenticated)
//   - serviceName: Identifies the embedding SDK service for the underlying client (e.g. "pamsh-accounts")
//   - retryStrategy: Optional retry configuration; nil skips retry setup
//
// Returns the initialized IdsecPVWABaseService or an error if validation or client creation fails.
func NewIdsecPVWABaseServiceWithRESTOptions(
	pvwaAuth *auth.IdsecPVWAAuth,
	serviceName string,
	retryStrategy common.IdsecClientRetryStrategy,
) (*IdsecPVWABaseService, error) {
	if pvwaAuth == nil {
		return nil, fmt.Errorf("PVWA authenticator is required")
	}
	if err := validatePVWAServiceName(serviceName); err != nil {
		return nil, err
	}
	if pvwaAuth.Token == nil {
		return nil, fmt.Errorf("PVWA authenticator has no active token")
	}
	client, err := pvwaclient.FromPVWAAuth(pvwaAuth, serviceName, retryStrategy)
	if err != nil {
		return nil, err
	}
	return &IdsecPVWABaseService{
		pvwaAuth: pvwaAuth,
		client:   client,
	}, nil
}

// PVWAAuth returns the PVWA authenticator for this service.
func (s *IdsecPVWABaseService) PVWAAuth() *auth.IdsecPVWAAuth {
	return s.pvwaAuth
}

// PVWAClient returns the PVWA service client for this service.
func (s *IdsecPVWABaseService) PVWAClient() *pvwaclient.IdsecPVWAServiceClient {
	return s.client
}

// AddExtraContextField is a no-op for PVWA-backed services.
// It satisfies the IdsecService interface without forwarding tool context to telemetry as pvwa does not support it.
func (s *IdsecPVWABaseService) AddExtraContextField(_, _, _ string) error {
	return nil
}

// ClearExtraContext is a no-op for PVWA-backed services.
// It satisfies the IdsecService interface without clearing telemetry metadata as pvwa does not support it.
func (s *IdsecPVWABaseService) ClearExtraContext() error {
	return nil
}
