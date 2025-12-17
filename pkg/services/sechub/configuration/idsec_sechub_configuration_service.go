package configuration

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	configurationmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/configuration/models"
)

const (
	sechubURL = "/api/configuration"
)

// IdsecSecHubConfigurationService is the service for interacting with Secrets Hub configuration
type IdsecSecHubConfigurationService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSecHubConfigurationService creates a new instance of IdsecSecHubConfigurationService.
func NewIdsecSecHubConfigurationService(authenticators ...auth.IdsecAuth) (*IdsecSecHubConfigurationService, error) {
	configurationService := &IdsecSecHubConfigurationService{}
	var configurationServiceInterface services.IdsecService = configurationService
	baseService, err := services.NewIdsecBaseService(configurationServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "secretshub", ".", "", configurationService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}
	configurationService.client = client
	configurationService.ispAuth = ispAuth
	configurationService.IdsecBaseService = baseService
	return configurationService, nil
}

func (s *IdsecSecHubConfigurationService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// Configuration retrieves the configuration info from the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/r3a0vv9er2enm-view-configuration
func (s *IdsecSecHubConfigurationService) Configuration() (*configurationmodels.IdsecSecHubGetConfiguration, error) {
	s.Logger.Info("Getting configuration")
	response, err := s.client.Get(context.Background(), sechubURL, nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get configuration - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	configurationJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var configurationinfo configurationmodels.IdsecSecHubGetConfiguration
	err = mapstructure.Decode(configurationJSON, &configurationinfo)
	if err != nil {
		return nil, err
	}
	return &configurationinfo, nil
}

// SetConfiguration updates the configuration info in the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/eko5hfu8sg16o-update-configuration
func (s *IdsecSecHubConfigurationService) SetConfiguration(setConfiguration *configurationmodels.IdsecSecHubSetConfiguration) (*configurationmodels.IdsecSecHubGetConfiguration, error) {
	s.Logger.Info("Updating configuration. Setting secret validity to [%d]", setConfiguration.SyncSettings.SecretValidity)
	setConfigurationJSON, err := common.SerializeJSONCamel(setConfiguration)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Patch(context.Background(), sechubURL, setConfigurationJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update configuration - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	configurationJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var configurationinfo configurationmodels.IdsecSecHubGetConfiguration
	err = mapstructure.Decode(configurationJSON, &configurationinfo)
	if err != nil {
		return nil, err
	}
	return &configurationinfo, nil
}

// ServiceConfig returns the service configuration for the IdsecSecHubConfigurationService.
func (s *IdsecSecHubConfigurationService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
