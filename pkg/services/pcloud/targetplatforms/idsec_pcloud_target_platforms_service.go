package targetplatforms

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
	targetplatformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/targetplatforms/models"
)

// API endpoint paths for target platform-related operations
const (
	importPlatformURL           = "api/platforms/import"
	targetPlatformsURL          = "api/platforms/targets"
	targetPlatformURL           = "api/platforms/targets/%d"
	exportTargetPlatformURL     = "api/platforms/targets/%d/export"
	duplicateTargetPlatformURL  = "api/platforms/targets/%d"
	activateTargetPlatformURL   = "api/platforms/targets/%d/activate"
	deactivateTargetPlatformURL = "api/platforms/targets/%d/deactivate"
)

// IdsecPCloudTargetPlatformsService is the service for managing pCloud Target Platforms.
type IdsecPCloudTargetPlatformsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService

	doGet    func(ctx context.Context, path string, params interface{}) (*http.Response, error)
	doPost   func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	doDelete func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error)
}

// NewIdsecPCloudTargetPlatformsService creates a new instance of IdsecPCloudTargetPlatformsService.
func NewIdsecPCloudTargetPlatformsService(authenticators ...auth.IdsecAuth) (*IdsecPCloudTargetPlatformsService, error) {
	pcloudTargetPlatformsService := &IdsecPCloudTargetPlatformsService{}
	var pcloudTargetPlatformsServiceInterface services.IdsecService = pcloudTargetPlatformsService
	baseService, err := services.NewIdsecBaseService(pcloudTargetPlatformsServiceInterface, authenticators...)
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
		pcloudTargetPlatformsService.refreshPCloudTargetPlatformsAuth,
		commonpcloud.DefaultPCloudRetryStrategy(),
	)
	if err != nil {
		return nil, err
	}

	pcloudTargetPlatformsService.IdsecBaseService = baseService
	pcloudTargetPlatformsService.IdsecISPBaseService = ispBaseService
	return pcloudTargetPlatformsService, nil
}

func (s *IdsecPCloudTargetPlatformsService) refreshPCloudTargetPlatformsAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecPCloudTargetPlatformsService) getOperation() func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	if s.doGet != nil {
		return s.doGet
	}
	return s.ISPClient().Get
}

func (s *IdsecPCloudTargetPlatformsService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPost != nil {
		return s.doPost
	}
	return s.ISPClient().Post
}

func (s *IdsecPCloudTargetPlatformsService) deleteOperation() func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
	if s.doDelete != nil {
		return s.doDelete
	}
	return s.ISPClient().Delete
}

func (s *IdsecPCloudTargetPlatformsService) listTargetPlatformsWithFilters(
	active bool,
	systemType string,
	periodicVerify bool,
	manualVerify bool,
	periodicChange bool,
	manualChange bool,
	automaticReconcile bool,
	manualReconcile bool,
) ([]*targetplatformsmodels.IdsecPCloudTargetPlatform, error) {
	args := []string{}
	if active {
		args = append(args, "active eq true")
	}
	if systemType != "" {
		args = append(args, fmt.Sprintf("systemType eq %s", systemType))
	}
	if periodicVerify {
		args = append(args, "periodicVerify eq true")
	}
	if manualVerify {
		args = append(args, "manualVerify eq true")
	}
	if periodicChange {
		args = append(args, "periodicChange eq true")
	}
	if manualChange {
		args = append(args, "manualChange eq true")
	}
	if automaticReconcile {
		args = append(args, "automaticReconcile eq true")
	}
	if manualReconcile {
		args = append(args, "manualReconcile eq true")
	}

	query := map[string]string{}
	if len(args) > 0 {
		query["filter"] = strings.Join(args, " AND ")
	}
	response, err := s.getOperation()(context.Background(), targetPlatformsURL, query)
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
		return nil, fmt.Errorf("failed to list target platforms - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
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
		return nil, fmt.Errorf("failed to list target platforms, unexpected result")
	}

	var platforms []*targetplatformsmodels.IdsecPCloudTargetPlatform
	if err := mapstructure.Decode(platformsJSON, &platforms); err != nil {
		return nil, fmt.Errorf("failed to decode target platforms: %v", err)
	}

	return platforms, nil
}

// List retrieves a list of IdsecPCloudTargetPlatform.
//
// Lists all the target platforms visible to the user.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-target-platforms.htm
func (s *IdsecPCloudTargetPlatformsService) List() ([]*targetplatformsmodels.IdsecPCloudTargetPlatform, error) {
	s.Logger.Info("Listing all target platforms")
	return s.listTargetPlatformsWithFilters(false, "", false, false, false, false, false, false)
}

// ListBy retrieves a list of IdsecPCloudTargetPlatform with filters.
//
// Lists target platforms by given filters.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-target-platforms.htm
func (s *IdsecPCloudTargetPlatformsService) ListBy(targetPlatformsFilter *targetplatformsmodels.IdsecPCloudTargetPlatformsFilter) ([]*targetplatformsmodels.IdsecPCloudTargetPlatform, error) {
	s.Logger.Info("Listing target platforms by filter [%+v]", targetPlatformsFilter)

	platforms, err := s.listTargetPlatformsWithFilters(
		targetPlatformsFilter.Active,
		targetPlatformsFilter.SystemType,
		targetPlatformsFilter.PeriodicVerify,
		targetPlatformsFilter.ManualVerify,
		targetPlatformsFilter.PeriodicChange,
		targetPlatformsFilter.ManualChange,
		targetPlatformsFilter.AutomaticReconcile,
		targetPlatformsFilter.ManualReconcile,
	)
	if err != nil {
		return nil, err
	}

	if targetPlatformsFilter.PlatformID != "" {
		var filtered []*targetplatformsmodels.IdsecPCloudTargetPlatform
		for _, platform := range platforms {
			matched, _ := filepath.Match(strings.ToLower(targetPlatformsFilter.PlatformID), strings.ToLower(platform.PlatformID))
			if matched {
				filtered = append(filtered, platform)
			}
		}
		platforms = filtered
	}

	if targetPlatformsFilter.Name != "" {
		var filtered []*targetplatformsmodels.IdsecPCloudTargetPlatform
		for _, platform := range platforms {
			matched, _ := filepath.Match(strings.ToLower(targetPlatformsFilter.Name), strings.ToLower(platform.Name))
			if matched {
				filtered = append(filtered, platform)
			}
		}
		platforms = filtered
	}

	if targetPlatformsFilter.Active {
		var filtered []*targetplatformsmodels.IdsecPCloudTargetPlatform
		for _, platform := range platforms {
			if platform.Active {
				filtered = append(filtered, platform)
			}
		}
		platforms = filtered
	}

	return platforms, nil
}

// Get retrieves a target platform by id.
//
// Gets a target platform by id.
// https://docs.cyberark.com/privilege-cloud-shared-services/Latest/en/Content/SDK/rest-api-get-target-platforms.htm
func (s *IdsecPCloudTargetPlatformsService) Get(getTargetPlatform *targetplatformsmodels.IdsecPCloudGetTargetPlatform) (*targetplatformsmodels.IdsecPCloudTargetPlatform, error) {
	s.Logger.Info("Retrieving target platform [%d]", getTargetPlatform.TargetPlatformID)

	platforms, err := s.List()
	if err != nil {
		return nil, err
	}

	for _, platform := range platforms {
		if platform.ID == getTargetPlatform.TargetPlatformID {
			return platform, nil
		}
	}

	return nil, fmt.Errorf("failed to get target platform with id %d", getTargetPlatform.TargetPlatformID)
}

// Activate activates a target platform by id.
//
// Activates a target platform by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/SDK/rest-api-activate-target-platform.htm
func (s *IdsecPCloudTargetPlatformsService) Activate(activateTargetPlatform *targetplatformsmodels.IdsecPCloudActivateTargetPlatform) error {
	s.Logger.Info("Activating target platform [%d]", activateTargetPlatform.TargetPlatformID)

	response, err := s.postOperation()(context.Background(), fmt.Sprintf(activateTargetPlatformURL, activateTargetPlatform.TargetPlatformID), nil)
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
		return fmt.Errorf("failed to activate target platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	return nil
}

// Deactivate deactivates a target platform by id.
//
// Deactivates a target platform by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/SDK/rest-api-deactivate-target-platform.htm
func (s *IdsecPCloudTargetPlatformsService) Deactivate(deactivateTargetPlatform *targetplatformsmodels.IdsecPCloudDeactivateTargetPlatform) error {
	s.Logger.Info("Deactivating target platform [%d]", deactivateTargetPlatform.TargetPlatformID)

	response, err := s.postOperation()(context.Background(), fmt.Sprintf(deactivateTargetPlatformURL, deactivateTargetPlatform.TargetPlatformID), nil)
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
		return fmt.Errorf("failed to deactivate target platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	return nil
}

// Duplicate duplicates a target platform by id.
//
// Duplicates a target platform by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-duplicate-target-platforms.htm
func (s *IdsecPCloudTargetPlatformsService) Duplicate(duplicateTargetPlatform *targetplatformsmodels.IdsecPCloudDuplicateTargetPlatform) (*targetplatformsmodels.IdsecPCloudDuplicatedTargetPlatformInfo, error) {
	s.Logger.Info("Duplicating target platform [%d] to name [%s]", duplicateTargetPlatform.TargetPlatformID, duplicateTargetPlatform.Name)

	duplicateJSON, err := common.SerializeJSONCamel(duplicateTargetPlatform)
	if err != nil {
		return nil, err
	}
	delete(duplicateJSON, "targetPlatformId")

	response, err := s.postOperation()(context.Background(), fmt.Sprintf(duplicateTargetPlatformURL, duplicateTargetPlatform.TargetPlatformID), duplicateJSON)
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
		return nil, fmt.Errorf("failed to duplicate target platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	resultJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var duplicatedInfo targetplatformsmodels.IdsecPCloudDuplicatedTargetPlatformInfo
	if err := mapstructure.Decode(resultJSON, &duplicatedInfo); err != nil {
		return nil, fmt.Errorf("failed to decode duplicated target platform info: %v", err)
	}

	return &duplicatedInfo, nil
}

// Delete deletes a target platform by id.
//
// Deletes a target platform by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-delete-target-platform.htm
func (s *IdsecPCloudTargetPlatformsService) Delete(deleteTargetPlatform *targetplatformsmodels.IdsecPCloudDeleteTargetPlatform) error {
	s.Logger.Info("Deleting target platform [%d]", deleteTargetPlatform.TargetPlatformID)

	response, err := s.deleteOperation()(context.Background(), fmt.Sprintf(targetPlatformURL, deleteTargetPlatform.TargetPlatformID), nil, nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete target platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	return nil
}

// Stats retrieves the statistics of IdsecPCloudTargetPlatforms.
//
// Calculates target platforms stats.
func (s *IdsecPCloudTargetPlatformsService) Stats() (*targetplatformsmodels.IdsecPCloudTargetPlatformsStats, error) {
	s.Logger.Info("Calculating target platform statistics")

	platforms, err := s.List()
	if err != nil {
		return nil, err
	}

	stats := &targetplatformsmodels.IdsecPCloudTargetPlatformsStats{
		TargetPlatformsCount:             len(platforms),
		TargetPlatformsCountBySystemType: make(map[string]int),
	}

	activeCount := 0
	for _, platform := range platforms {
		if platform.Active {
			activeCount++
		}
		stats.TargetPlatformsCountBySystemType[platform.SystemType]++
	}
	stats.ActiveTargetPlatformsCount = activeCount

	return stats, nil
}

// Import imports a target platform from a zip file.
//
// Tries to import a target platform zip data.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ImportPlatform.htm
func (s *IdsecPCloudTargetPlatformsService) Import(importPlatform *targetplatformsmodels.IdsecPCloudImportTargetPlatform) (*targetplatformsmodels.IdsecPCloudTargetPlatform, error) {
	s.Logger.Info("Importing target platform from [%s]", importPlatform.PlatformZipPath)

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
		return nil, fmt.Errorf("failed to import target platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
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

	platforms, err := s.ListBy(&targetplatformsmodels.IdsecPCloudTargetPlatformsFilter{
		PlatformID: platformID,
	})
	if err != nil {
		return nil, err
	}

	if len(platforms) == 0 {
		return nil, fmt.Errorf("failed to find target platform after importing it")
	}

	return platforms[0], nil
}

// Export exports a target platform to a zip file.
//
// Exports a target platform zip data to a given folder by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/SDK/ExportPlatform.htm
func (s *IdsecPCloudTargetPlatformsService) Export(exportPlatform *targetplatformsmodels.IdsecPCloudExportTargetPlatform) error {
	s.Logger.Info("Exporting target platform [%d] to folder [%s]", exportPlatform.TargetPlatformID, exportPlatform.OutputFolder)

	targetPlatform, err := s.Get(&targetplatformsmodels.IdsecPCloudGetTargetPlatform{
		TargetPlatformID: exportPlatform.TargetPlatformID,
	})
	if err != nil {
		return err
	}

	if err := os.MkdirAll(exportPlatform.OutputFolder, 0755); err != nil {
		return fmt.Errorf("failed to create output folder: %v", err)
	}

	response, err := s.postOperation()(context.Background(), fmt.Sprintf(exportTargetPlatformURL, exportPlatform.TargetPlatformID), nil)
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
		return fmt.Errorf("failed to export target platform - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read export data: %v", err)
	}
	outputPath := filepath.Join(exportPlatform.OutputFolder, targetPlatform.PlatformID)
	if err := os.WriteFile(fmt.Sprintf("%s.zip", outputPath), data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %v", err)
	}

	return nil
}

// ServiceConfig returns the service configuration for the IdsecPCloudTargetPlatformsService.
func (s *IdsecPCloudTargetPlatformsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
