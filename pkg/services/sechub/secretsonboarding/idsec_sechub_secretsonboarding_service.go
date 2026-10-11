package secretsonboarding

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	onboardingmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretsonboarding/models"
)

const onboardingURL = "/api/secrets-onboarding/%s/%s"

// IdsecSecHubSecretOnboardingService is the service for onboarding secrets from external
// secret stores to PAM via Secrets Hub.
type IdsecSecHubSecretOnboardingService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSecHubSecretOnboardingService creates a new instance of IdsecSecHubSecretOnboardingService.
func NewIdsecSecHubSecretOnboardingService(authenticators ...auth.IdsecAuth) (*IdsecSecHubSecretOnboardingService, error) {
	onboardingService := &IdsecSecHubSecretOnboardingService{}
	var onboardingServiceInterface services.IdsecService = onboardingService
	baseService, err := services.NewIdsecBaseService(onboardingServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "secretshub", ".", "", onboardingService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}
	// Required as endpoints are currently beta
	ispBaseService.ISPClient().UpdateHeaders(map[string]string{
		"Accept": "application/x.secretshub.beta+json",
	})

	onboardingService.IdsecBaseService = baseService
	onboardingService.IdsecISPBaseService = ispBaseService
	return onboardingService, nil
}

func (s *IdsecSecHubSecretOnboardingService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// ServiceConfig returns the service configuration for the SecHub secret onboarding service.
func (s *IdsecSecHubSecretOnboardingService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

// This method is intended for Terraform use only.
// Create onboards a secret to PAM by calling POST /api/secrets-onboarding/{source}/{target}.
// Returns the input request as state on success (the API returns 204 No Content with no body),
// or an error if the request fails or the response is not 204 No Content.
func (s *IdsecSecHubSecretOnboardingService) Create(req *onboardingmodels.IdsecSecHubOnboardSecret) (*onboardingmodels.IdsecSecHubOnboardSecret, error) {
	s.Logger.Info("Onboarding secret [%s] to PAM", req.SecretID)
	bodyJSON, err := common.SerializeJSONCamel(req)
	if err != nil {
		return nil, err
	}
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(onboardingURL, req.SourceStoreType, req.TargetStoreType), bodyJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("failed to onboard secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return req, nil
}
