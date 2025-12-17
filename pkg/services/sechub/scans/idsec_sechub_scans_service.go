package scans

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
	scansmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/scans/models"
)

const (
	sechubURL  = "/api/scans"
	triggerURL = "/api/scan-definitions/%s/%s/scan"
)

// IdsecSecHubScansPage is a page of IdsecSecHubScan items.
type IdsecSecHubScansPage = common.IdsecPage[scansmodels.IdsecSecHubScan]

// IdsecSecHubScansService is the service for interacting with Secrets Hub scans
type IdsecSecHubScansService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSecHubScansService creates a new instance of IdsecSecHubscansService.
func NewIdsecSecHubScansService(authenticators ...auth.IdsecAuth) (*IdsecSecHubScansService, error) {
	scansService := &IdsecSecHubScansService{}
	var scansServiceInterface services.IdsecService = scansService
	baseService, err := services.NewIdsecBaseService(scansServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "secretshub", ".", "", scansService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}
	// Required as endpoints are currently beta
	client.UpdateHeaders(map[string]string{
		"Accept": "application/x.secretshub.beta+json",
	})
	scansService.client = client
	scansService.ispAuth = ispAuth
	scansService.IdsecBaseService = baseService
	return scansService, nil
}

func (s *IdsecSecHubScansService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// Scans retrieves the scans info from the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/78cprz38emhrb-get-scans
func (s *IdsecSecHubScansService) Scans() (<-chan *IdsecSecHubScansPage, error) {
	s.Logger.Info("Getting scans")

	results := make(chan *IdsecSecHubScansPage)
	go func() {
		defer close(results)
		response, err := s.client.Get(context.Background(), sechubURL, nil)
		if err != nil {
			s.Logger.Error("Failed to list filters: %v", err)
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				common.GlobalLogger.Warning("Error closing response body")
			}
		}(response.Body)
		if response.StatusCode != http.StatusOK {
			s.Logger.Error("Failed to list Secret Store Scans - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
			return
		}
		result, err := common.DeserializeJSONSnake(response.Body)
		if err != nil {
			s.Logger.Error("Failed to decode response: %v", err)
			return
		}
		resultMap := result.(map[string]interface{})
		var scansJSON []interface{}
		if scans, ok := resultMap["scans"]; ok {
			scansJSON = scans.([]interface{})
		} else {
			s.Logger.Error("Failed to list Secret Store scans, unexpected result")
			return
		}
		for i, scansMember := range scansJSON {
			if scansMemberMap, ok := scansMember.(map[string]interface{}); ok {
				if ID, ok := scansMemberMap["id"]; ok {
					scansJSON[i].(map[string]interface{})["id"] = ID
				}
			}
		}
		var scans []*scansmodels.IdsecSecHubScan
		if err := mapstructure.Decode(scansJSON, &scans); err != nil {
			s.Logger.Error("Failed to validate Secret Store scans: %v", err)
			return
		}

		results <- &IdsecSecHubScansPage{Items: scans}
	}()
	return results, nil
}

// TriggerScan triggers scans in the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/kyc9azwliw2xa-trigger-scan
func (s *IdsecSecHubScansService) TriggerScan(triggerScan *scansmodels.IdsecSecHubTriggerScans) (*scansmodels.IdsecSecHubScanIDs, error) {
	bodyMap := scansmodels.IdsecSecHubScanMap{
		Scope: scansmodels.IdsecSecHubSecretStoreIds{
			SecretStoresIds: triggerScan.SecretStoresIds,
		},
	}
	bodyMapJSON, err := common.SerializeJSONCamel(bodyMap)
	if err != nil {
		return nil, err
	}
	s.Logger.Info("Triggering scan. Scan ID %s", triggerScan.ID)
	response, err := s.client.Post(context.Background(), fmt.Sprintf(triggerURL, triggerScan.Type, triggerScan.ID), bodyMapJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("failed to update scans - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	scansJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var scans scansmodels.IdsecSecHubScanIDs
	err = mapstructure.Decode(scansJSON, &scans)
	if err != nil {
		return nil, err
	}
	return &scans, nil
}

// ScansStats retrieves statistics about scans.
func (s *IdsecSecHubScansService) ScansStats() (*scansmodels.IdsecSecHubScanStats, error) {
	s.Logger.Info("Retrieving scan stats")
	scansChan, err := s.Scans()
	if err != nil {
		return nil, err
	}
	scans := make([]*scansmodels.IdsecSecHubScan, 0)
	for page := range scansChan {
		scans = append(scans, page.Items...)
	}
	var scanStats scansmodels.IdsecSecHubScanStats
	scanStats.ScansCount = len(scans)
	scanStats.ScansCountByCreator = make(map[string]int)
	for _, scans := range scans {
		if _, ok := scanStats.ScansCountByCreator[scans.CreatedBy]; !ok {
			scanStats.ScansCountByCreator[scans.CreatedBy] = 0
		}
		scanStats.ScansCountByCreator[scans.CreatedBy]++
	}
	return &scanStats, nil
}

// ServiceConfig returns the service scans for the IdsecSecHubScansService.
func (s *IdsecSecHubScansService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
