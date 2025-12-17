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
	platformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/models"
)

// API endpoint paths for platform-related operations
const (
	platformsURL                = "api/platforms"
	platformURL                 = "api/platforms/%s"
	importPlatformURL           = "api/platforms/import"
	exportPlatformURL           = "api/platforms/%s/export"
	targetPlatformsURL          = "api/platforms/targets"
	targetPlatformURL           = "api/platforms/targets/%d"
	exportTargetPlatformURL     = "api/platforms/targets/%d/export"
	duplicateTargetPlatformURL  = "api/platforms/targets/%d"
	activateTargetPlatformURL   = "api/platforms/targets/%d/activate"
	deactivateTargetPlatformURL = "api/platforms/targets/%d/deactivate"
)

// IdsecPCloudPlatformsService is the service for managing pCloud Platforms.
type IdsecPCloudPlatformsService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient

	doGet    func(ctx context.Context, path string, params interface{}) (*http.Response, error)
	doPost   func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	doDelete func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error)
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
	client, err := isp.FromISPAuth(ispAuth, "privilegecloud", ".", "passwordvault", pcloudPlatformsService.refreshPCloudPlatformsAuth)
	if err != nil {
		return nil, err
	}
	pcloudPlatformsService.client = client
	pcloudPlatformsService.ispAuth = ispAuth
	pcloudPlatformsService.IdsecBaseService = baseService
	return pcloudPlatformsService, nil
}

func (s *IdsecPCloudPlatformsService) refreshPCloudPlatformsAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecPCloudPlatformsService) getOperation() func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	if s.doGet != nil {
		return s.doGet
	}
	return s.client.Get
}

func (s *IdsecPCloudPlatformsService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPost != nil {
		return s.doPost
	}
	return s.client.Post
}

func (s *IdsecPCloudPlatformsService) deleteOperation() func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
	if s.doDelete != nil {
		return s.doDelete
	}
	return s.client.Delete
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

// ListPlatforms retrieves a list of IdsecPCloudPlatform.
//
// Lists all the platforms visible to the user.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-platforms.htm
func (s *IdsecPCloudPlatformsService) ListPlatforms() ([]*platformsmodels.IdsecPCloudPlatform, error) {
	s.Logger.Info("Listing all platforms")
	return s.listPlatformsWithFilters(false, "", "")
}

// ListPlatformsBy retrieves a list of IdsecPCloudPlatform with filters.
//
// Lists platforms by given filters.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-platforms.htm
func (s *IdsecPCloudPlatformsService) ListPlatformsBy(platformsFilter *platformsmodels.IdsecPCloudPlatformsFilter) ([]*platformsmodels.IdsecPCloudPlatform, error) {
	s.Logger.Info("Listing platforms by filter [%+v]", platformsFilter)
	return s.listPlatformsWithFilters(
		platformsFilter.Active,
		platformsFilter.PlatformType,
		platformsFilter.PlatformName,
	)
}

// Platform retrieves a platform by id.
//
// Retrieves a platform by id, returns either IdsecPCloudPlatform or IdsecPCloudPlatformDetails
// depending on the API response format.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/GetPlatformDetails.htm
func (s *IdsecPCloudPlatformsService) Platform(getPlatform *platformsmodels.IdsecPCloudGetPlatform) (*platformsmodels.IdsecPCloudPlatformDetails, error) {
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

// ImportPlatform imports a platform from a zip file.
//
// Tries to import a platform zip data.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ImportPlatform.htm
func (s *IdsecPCloudPlatformsService) ImportPlatform(importPlatform *platformsmodels.IdsecPCloudImportPlatform) (*platformsmodels.IdsecPCloudPlatformDetails, error) {
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

	return s.Platform(&platformsmodels.IdsecPCloudGetPlatform{PlatformID: platformID})
}

// ImportTargetPlatform imports a target platform from a zip file.
//
// Tries to import a target platform zip data.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ImportPlatform.htm
func (s *IdsecPCloudPlatformsService) ImportTargetPlatform(importPlatform *platformsmodels.IdsecPCloudImportTargetPlatform) (*platformsmodels.IdsecPCloudTargetPlatform, error) {
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

	platforms, err := s.ListTargetPlatformsBy(&platformsmodels.IdsecPCloudTargetPlatformsFilter{
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

// ExportPlatform exports a platform to a zip file.
//
// Exports a platform zip data to a given folder by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/SDK/ExportPlatform.htm
func (s *IdsecPCloudPlatformsService) ExportPlatform(exportPlatform *platformsmodels.IdsecPCloudExportPlatform) error {
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

// ExportTargetPlatform exports a target platform to a zip file.
//
// Exports a target platform zip data to a given folder by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/SDK/ExportPlatform.htm
func (s *IdsecPCloudPlatformsService) ExportTargetPlatform(exportPlatform *platformsmodels.IdsecPCloudExportTargetPlatform) error {
	s.Logger.Info("Exporting target platform [%d] to folder [%s]", exportPlatform.TargetPlatformID, exportPlatform.OutputFolder)

	targetPlatform, err := s.TargetPlatform(&platformsmodels.IdsecPCloudGetTargetPlatform{
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

// PlatformsStats retrieves the statistics of IdsecPCloudPlatforms.
//
// Calculates platforms stats.
func (s *IdsecPCloudPlatformsService) PlatformsStats() (*platformsmodels.IdsecPCloudPlatformsStats, error) {
	s.Logger.Info("Calculating platform statistics")

	platforms, err := s.ListPlatforms()
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

func (s *IdsecPCloudPlatformsService) listTargetPlatformsWithFilters(
	active bool,
	systemType string,
	periodicVerify bool,
	manualVerify bool,
	periodicChange bool,
	manualChange bool,
	automaticReconcile bool,
	manualReconcile bool,
) ([]*platformsmodels.IdsecPCloudTargetPlatform, error) {
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

	var platforms []*platformsmodels.IdsecPCloudTargetPlatform
	if err := mapstructure.Decode(platformsJSON, &platforms); err != nil {
		return nil, fmt.Errorf("failed to decode target platforms: %v", err)
	}

	return platforms, nil
}

// ListTargetPlatforms retrieves a list of IdsecPCloudTargetPlatform.
//
// Lists all the target platforms visible to the user.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-target-platforms.htm
func (s *IdsecPCloudPlatformsService) ListTargetPlatforms() ([]*platformsmodels.IdsecPCloudTargetPlatform, error) {
	s.Logger.Info("Listing all target platforms")
	return s.listTargetPlatformsWithFilters(false, "", false, false, false, false, false, false)
}

// ListTargetPlatformsBy retrieves a list of IdsecPCloudTargetPlatform with filters.
//
// Lists target platforms by given filters.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-get-target-platforms.htm
func (s *IdsecPCloudPlatformsService) ListTargetPlatformsBy(targetPlatformsFilter *platformsmodels.IdsecPCloudTargetPlatformsFilter) ([]*platformsmodels.IdsecPCloudTargetPlatform, error) {
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
		var filtered []*platformsmodels.IdsecPCloudTargetPlatform
		for _, platform := range platforms {
			matched, _ := filepath.Match(strings.ToLower(targetPlatformsFilter.PlatformID), strings.ToLower(platform.PlatformID))
			if matched {
				filtered = append(filtered, platform)
			}
		}
		platforms = filtered
	}

	if targetPlatformsFilter.Name != "" {
		var filtered []*platformsmodels.IdsecPCloudTargetPlatform
		for _, platform := range platforms {
			matched, _ := filepath.Match(strings.ToLower(targetPlatformsFilter.Name), strings.ToLower(platform.Name))
			if matched {
				filtered = append(filtered, platform)
			}
		}
		platforms = filtered
	}

	if targetPlatformsFilter.Active {
		var filtered []*platformsmodels.IdsecPCloudTargetPlatform
		for _, platform := range platforms {
			if platform.Active {
				filtered = append(filtered, platform)
			}
		}
		platforms = filtered
	}

	return platforms, nil
}

// TargetPlatform retrieves a target platform by id.
//
// Gets a target platform by id.
// https://docs.cyberark.com/privilege-cloud-shared-services/Latest/en/Content/SDK/rest-api-get-target-platforms.htm
func (s *IdsecPCloudPlatformsService) TargetPlatform(getTargetPlatform *platformsmodels.IdsecPCloudGetTargetPlatform) (*platformsmodels.IdsecPCloudTargetPlatform, error) {
	s.Logger.Info("Retrieving target platform [%d]", getTargetPlatform.TargetPlatformID)

	platforms, err := s.ListTargetPlatforms()
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

// ActivateTargetPlatform activates a target platform by id.
//
// Activates a target platform by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/SDK/rest-api-activate-target-platform.htm
func (s *IdsecPCloudPlatformsService) ActivateTargetPlatform(activateTargetPlatform *platformsmodels.IdsecPCloudActivateTargetPlatform) error {
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

// DeactivateTargetPlatform deactivates a target platform by id.
//
// Deactivates a target platform by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/SDK/rest-api-deactivate-target-platform.htm
func (s *IdsecPCloudPlatformsService) DeactivateTargetPlatform(deactivateTargetPlatform *platformsmodels.IdsecPCloudDeactivateTargetPlatform) error {
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

// DuplicateTargetPlatform duplicates a target platform by id.
//
// Duplicates a target platform by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-duplicate-target-platforms.htm
func (s *IdsecPCloudPlatformsService) DuplicateTargetPlatform(duplicateTargetPlatform *platformsmodels.IdsecPCloudDuplicateTargetPlatform) (*platformsmodels.IdsecPCloudDuplicatedTargetPlatformInfo, error) {
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

	var duplicatedInfo platformsmodels.IdsecPCloudDuplicatedTargetPlatformInfo
	if err := mapstructure.Decode(resultJSON, &duplicatedInfo); err != nil {
		return nil, fmt.Errorf("failed to decode duplicated target platform info: %v", err)
	}

	return &duplicatedInfo, nil
}

// DeleteTargetPlatform deletes a target platform by id.
//
// Deletes a target platform by id.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/rest-api-delete-target-platform.htm
func (s *IdsecPCloudPlatformsService) DeleteTargetPlatform(deleteTargetPlatform *platformsmodels.IdsecPCloudDeleteTargetPlatform) error {
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

// TargetPlatformsStats retrieves the statistics of IdsecPCloudTargetPlatforms.
//
// Calculates target platforms stats.
func (s *IdsecPCloudPlatformsService) TargetPlatformsStats() (*platformsmodels.IdsecPCloudTargetPlatformsStats, error) {
	s.Logger.Info("Calculating target platform statistics")

	platforms, err := s.ListTargetPlatforms()
	if err != nil {
		return nil, err
	}

	stats := &platformsmodels.IdsecPCloudTargetPlatformsStats{
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

// ServiceConfig returns the service configuration for the IdsecPCloudPlatformsService.
func (s *IdsecPCloudPlatformsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
