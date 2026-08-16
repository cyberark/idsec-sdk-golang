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
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
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
	*services.IdsecBaseService
	*services.IdsecISPBaseService
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
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "secretshub", ".", "", scansService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}
	// Required as endpoints are currently beta
	ispBaseService.ISPClient().UpdateHeaders(map[string]string{
		"Accept": "application/x.secretshub.beta+json",
	})

	scansService.IdsecBaseService = baseService
	scansService.IdsecISPBaseService = ispBaseService
	return scansService, nil
}

func (s *IdsecSecHubScansService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func decodeScansFromResultMap(resultMap map[string]interface{}) ([]*scansmodels.IdsecSecHubScan, error) {
	items, err := pagination.ExtractItemsFromResult(resultMap, "Secret Store scans", "scans")
	if err != nil {
		return nil, err
	}
	var scans []*scansmodels.IdsecSecHubScan
	if err := mapstructure.Decode(items, &scans); err != nil {
		return nil, fmt.Errorf("failed to validate Secret Store scans: %w", err)
	}
	return scans, nil
}

// Get retrieves the scans info from the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/78cprz38emhrb-get-scans
//
// This endpoint is not OData-paginated: it returns every scan in a single response, so
// NextQuery always stops after the first page (matching the previous non-looping behavior).
func (s *IdsecSecHubScansService) Get() (<-chan *IdsecSecHubScansPage, error) {
	s.Logger.Info("Getting scans")

	return pagination.ListAllPaginated[scansmodels.IdsecSecHubScan](
		context.Background(),
		pagination.HTTPGetFetch(s.ISPClient(), sechubURL, nil),
		pagination.ListPaginatedConfig[scansmodels.IdsecSecHubScan]{
			ResourceName: "Secret Store scans",
			Decode:       decodeScansFromResultMap,
			NextQuery: func(_ map[string]interface{}, _ map[string]string) (map[string]string, bool) {
				return nil, false
			},
		},
	)
}

// Trigger triggers scans in the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/kyc9azwliw2xa-trigger-scan
func (s *IdsecSecHubScansService) Trigger(triggerScan *scansmodels.IdsecSecHubTriggerScans) (*scansmodels.IdsecSecHubScanIDs, error) {
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
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(triggerURL, triggerScan.Type, triggerScan.ID), bodyMapJSON)
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

// Stats retrieves statistics about scans.
func (s *IdsecSecHubScansService) Stats() (*scansmodels.IdsecSecHubScanStats, error) {
	s.Logger.Info("Retrieving scan stats")
	scansChan, err := s.Get()
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
