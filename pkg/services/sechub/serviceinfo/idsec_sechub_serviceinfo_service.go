package serviceinfo

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
	serviceinfomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/serviceinfo/models"
)

const (
	sechubURL = "/api/info"
)

// IdsecSecHubServiceInfoService is the service for retrieve Secrets Hub service Info
type IdsecSecHubServiceInfoService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSecHubServiceInfoService creates a new instance of IdsecSecHubServiceInfoService.
func NewIdsecSecHubServiceInfoService(authenticators ...auth.IdsecAuth) (*IdsecSecHubServiceInfoService, error) {
	serviceInfoService := &IdsecSecHubServiceInfoService{}
	var serviceInfoServiceInterface services.IdsecService = serviceInfoService
	baseService, err := services.NewIdsecBaseService(serviceInfoServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "secretshub", ".", "", serviceInfoService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}
	serviceInfoService.client = client
	serviceInfoService.ispAuth = ispAuth
	serviceInfoService.IdsecBaseService = baseService
	return serviceInfoService, nil
}

func (s *IdsecSecHubServiceInfoService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// ServiceInfo retrieves the service info from the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/b7c22j9aexv8r-service-info
func (s *IdsecSecHubServiceInfoService) ServiceInfo() (*serviceinfomodels.IdsecSecHubGetServiceInfo, error) {
	s.Logger.Info("Getting serviceinfo")
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
		return nil, fmt.Errorf("failed to get service info - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	serviceinfoJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var serviceinfo serviceinfomodels.IdsecSecHubGetServiceInfo
	err = mapstructure.Decode(serviceinfoJSON, &serviceinfo)
	if err != nil {
		return nil, err
	}
	return &serviceinfo, nil
}

// ServiceConfig returns the service configuration for the IdsecSecHubServiceInfoService.
func (s *IdsecSecHubServiceInfoService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
