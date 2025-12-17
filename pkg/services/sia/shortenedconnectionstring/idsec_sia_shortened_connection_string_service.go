package shortenedconnectionstring

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	shortenedconnectionstringmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/shortenedconnectionstring/models"

	"io"
	"net/http"
)

const (
	generateShortenedConnectionStringURL = "api/guidance/aliases"
)

// IdsecSIAShortenedConnectionStringService is a struct that implements the IdsecService interface and provides functionality for shortened connection string for SIA.
type IdsecSIAShortenedConnectionStringService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSIAShortenedConnectionStringService creates a new instance of IdsecSIAShortenedConnectionStringService with the provided authenticators.
func NewIdsecSIAShortenedConnectionStringService(authenticators ...auth.IdsecAuth) (*IdsecSIAShortenedConnectionStringService, error) {
	shortenedConnectionStringService := &IdsecSIAShortenedConnectionStringService{}
	var shortenedConnectionStringServiceInterface services.IdsecService = shortenedConnectionStringService
	baseService, err := services.NewIdsecBaseService(shortenedConnectionStringServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", shortenedConnectionStringService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	shortenedConnectionStringService.client = client
	shortenedConnectionStringService.ispAuth = ispAuth
	shortenedConnectionStringService.IdsecBaseService = baseService
	return shortenedConnectionStringService, nil
}

func (s *IdsecSIAShortenedConnectionStringService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// Generate generates a shortened connection string for the provided raw connection string.
func (s *IdsecSIAShortenedConnectionStringService) Generate(
	generateShortenedConnectionString *shortenedconnectionstringmodels.IdsecSIAGenerateShortenedConnectionString) (*shortenedconnectionstringmodels.IdsecSIAGenerateShortenedConnectionStringResponse, error) {
	s.Logger.Info("Generating shortened connection string for [%s]", generateShortenedConnectionString.RawConnectionString)
	var generateShortenedConnectionStringJSON map[string]interface{}
	err := mapstructure.Decode(generateShortenedConnectionString, &generateShortenedConnectionStringJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Post(context.Background(), generateShortenedConnectionStringURL, generateShortenedConnectionStringJSON)
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
		return nil, fmt.Errorf("failed to generate shortened connection string - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	generateShortenedConnectionStringResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var generateShortenedConnectionStringResponse shortenedconnectionstringmodels.IdsecSIAGenerateShortenedConnectionStringResponse
	err = mapstructure.Decode(generateShortenedConnectionStringResponseJSON, &generateShortenedConnectionStringResponse)
	if err != nil {
		return nil, err
	}
	return &generateShortenedConnectionStringResponse, nil
}

// ServiceConfig returns the service configuration for the IdsecSIASSHCAService.
func (s *IdsecSIAShortenedConnectionStringService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
