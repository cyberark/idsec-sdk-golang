package platforms

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	commonpcloud "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/common"
	platformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/models"
)

// API endpoint paths for platform-related operations
const (
	platformsURL      = "api/platforms"
	platformURL       = "api/platforms/%s"
	importPlatformURL = "api/platforms/import"
	exportPlatformURL = "api/platforms/%s/export"
)

// IdsecPCloudPlatformsService is the service for managing pCloud Platforms.
type IdsecPCloudPlatformsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService

	doGet  func(ctx context.Context, path string, params interface{}) (*http.Response, error)
	doPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
}

// NewIdsecPCloudPlatformsService creates a new instance of IdsecPCloudPlatformsService.
func NewIdsecPCloudPlatformsService(authenticators ...auth.IdsecAuth) (*IdsecPCloudPlatformsService, error) {
	pcloudPlatformsService := &IdsecPCloudPlatformsService{}
	var pcloudPlatformsServiceInterface services.IdsecService = pcloudPlatformsService
	baseService, err := services.NewIdsecBaseService(pcloudPlatformsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseServiceWithRetry(
		ispAuth,
		"privilegecloud",
		".",
		"passwordvault",
		pcloudPlatformsService.refreshPCloudPlatformsAuth,
		commonpcloud.DefaultPCloudRetryStrategy(),
	)
	if err != nil {
		return nil, err
	}

	pcloudPlatformsService.IdsecBaseService = baseService
	pcloudPlatformsService.IdsecISPBaseService = ispBaseService
	return pcloudPlatformsService, nil
}

func (s *IdsecPCloudPlatformsService) refreshPCloudPlatformsAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecPCloudPlatformsService) getOperation() func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	if s.doGet != nil {
		return s.doGet
	}
	return s.ISPClient().Get
}

func (s *IdsecPCloudPlatformsService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPost != nil {
		return s.doPost
	}
	return s.ISPClient().Post
}

func (s *IdsecPCloudPlatformsService) listPlatformsWithFilters(
	active bool,
	platformType string,
	platformName string,
) ([]*platformsmodels.IdsecPCloudPlatform, error) {
	query := map[string]string{}
	if active {
		query["Active"] = "true"
	}
	if platformType != "" {
		query["PlatformType"] = platformType
	}
	if platformName != "" {
		query["Search"] = platformName
	}

	response, err := s.getOperation()(context.Background(), platformsURL, query)
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
		return nil, fmt.Errorf("failed to list platforms - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	result, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	resultMap := result.(map[string]interface{})
	var platformsJSON []interface{}
	if value, ok := resultMap["platforms"]; ok {
		platformsJSON = value.([]interface{})
	} else {
		return nil, fmt.Errorf("failed to list platforms, unexpected result")
	}

	// Platform type may come in uppercase, lowercase it
	for _, platform := range platformsJSON {
		if platformMap, ok := platform.(map[string]interface{}); ok {
			if general, ok := platformMap["general"].(map[string]interface{}); ok {
				if platformType, ok := general["platform_type"].(string); ok {
					general["platform_type"] = strings.ToLower(platformType)
				}
			}
		}
	}

	var platforms []*platformsmodels.IdsecPCloudPlatform
	if err := mapstructure.Decode(platformsJSON, &platforms); err != nil {
		return nil, fmt.Errorf("failed to decode platforms: %v", err)
	}

	return platforms, nil
}

// List retrieves a list of IdsecPCloudPlatform.
//
// Lists all the platforms visible to the user.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-platforms.htm
func (s *IdsecPCloudPlatformsService) List() ([]*platformsmodels.IdsecPCloudPlatform, error) {
	s.Logger.Info("Listing all platforms")
	return s.listPlatformsWithFilters(false, "", "")
}

// ListBy retrieves a list of IdsecPCloudPlatform with filters.
//
// Lists platforms by given filters.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-platforms.htm
func (s *IdsecPCloudPlatformsService) ListBy(platformsFilter *platformsmodels.IdsecPCloudPlatformsFilter) ([]*platformsmodels.IdsecPCloudPlatform, error) {
	s.Logger.Info("Listing platforms by filter [%+v]", platformsFilter)
	return s.listPlatformsWithFilters(
		platformsFilter.Active,
		platformsFilter.PlatformType,
		platformsFilter.PlatformName,
	)
}

// Get retrieves a platform by id.
//
// Retrieves a platform by id, returns either IdsecPCloudPlatform or IdsecPCloudPlatformDetails
// depending on the API response format.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/GetPlatformDetails.htm
func (s *IdsecPCloudPlatformsService) Get(getPlatform *platformsmodels.IdsecPCloudGetPlatform) (*platformsmodels.IdsecPCloudPlatformDetails, error) {
	s.Logger.Info("Retrieving platform [%s]", getPlatform.PlatformID)
	response, err := s.getOperation()(context.Background(), fmt.Sprintf(platformURL, getPlatform.PlatformID), nil)
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
		return nil, fmt.Errorf("failed to retrieve platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	platformJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	// Fallback to new Details API model
	var platformDetails platformsmodels.IdsecPCloudPlatformDetails
	if err := mapstructure.Decode(platformJSON, &platformDetails); err != nil {
		return nil, fmt.Errorf("failed to decode platform: %v", err)
	}

	return &platformDetails, nil
}

// Import imports a platform from a zip file.
//
// Tries to import a platform zip data.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ImportPlatform.htm
func (s *IdsecPCloudPlatformsService) Import(importPlatform *platformsmodels.IdsecPCloudImportPlatform) (*platformsmodels.IdsecPCloudPlatformDetails, error) {
	s.Logger.Info("Importing platform from [%s]", importPlatform.PlatformZipPath)

	if _, err := os.Stat(importPlatform.PlatformZipPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("given path [%s] does not exist or is invalid", importPlatform.PlatformZipPath)
	}

	zipData, err := os.ReadFile(importPlatform.PlatformZipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read platform zip file: %v", err)
	}

	encodedData := base64.StdEncoding.EncodeToString(zipData)
	requestBody := map[string]interface{}{
		"ImportFile": encodedData,
	}

	response, err := s.postOperation()(context.Background(), importPlatformURL, requestBody)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to import platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	resultJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	resultMap := resultJSON.(map[string]interface{})
	platformID, ok := resultMap["platform_id"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse platform id from import response")
	}

	return s.Get(&platformsmodels.IdsecPCloudGetPlatform{PlatformID: platformID})
}

// Export exports a platform to a zip file.
//
// Exports a platform zip data to a given folder by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/SDK/ExportPlatform.htm
func (s *IdsecPCloudPlatformsService) Export(exportPlatform *platformsmodels.IdsecPCloudExportPlatform) error {
	s.Logger.Info("Exporting platform [%s] to folder [%s]", exportPlatform.PlatformID, exportPlatform.OutputFolder)

	if err := os.MkdirAll(exportPlatform.OutputFolder, 0755); err != nil {
		return fmt.Errorf("failed to create output folder: %v", err)
	}

	response, err := s.postOperation()(context.Background(), fmt.Sprintf(exportPlatformURL, exportPlatform.PlatformID), nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to export platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read export data: %v", err)
	}

	outputPath := filepath.Join(exportPlatform.OutputFolder, exportPlatform.PlatformID)
	if err := os.WriteFile(fmt.Sprintf("%s.zip", outputPath), data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %v", err)
	}

	return nil
}

// Stats retrieves the statistics of IdsecPCloudPlatforms.
//
// Calculates platforms stats.
func (s *IdsecPCloudPlatformsService) Stats() (*platformsmodels.IdsecPCloudPlatformsStats, error) {
	s.Logger.Info("Calculating platform statistics")

	platforms, err := s.List()
	if err != nil {
		return nil, err
	}

	stats := &platformsmodels.IdsecPCloudPlatformsStats{
		PlatformsCount:       len(platforms),
		PlatformsCountByType: make(map[string]int),
	}

	for _, platform := range platforms {
		stats.PlatformsCountByType[platform.General.PlatformType]++
	}

	return stats, nil
}

// ServiceConfig returns the service configuration for the IdsecPCloudPlatformsService.
func (s *IdsecPCloudPlatformsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
