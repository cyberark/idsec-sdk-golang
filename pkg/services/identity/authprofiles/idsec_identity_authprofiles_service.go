package authprofiles

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	authprofilesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles/models"
)

const (
	saveProfileURL   = "AuthProfile/SaveProfile"
	deleteProfileURL = "AuthProfile/DeleteProfile"
	listProfilesURL  = "AuthProfile/GetDecoratedProfileList"
	getProfileURL    = "AuthProfile/GetProfile"
)

// IdsecIdentityAuthProfilesService is the service for managing identity auth profiles.
type IdsecIdentityAuthProfilesService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient

	DoPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
}

// NewIdsecIdentityAuthProfilesService creates a new instance of IdsecIdentityAuthProfilesService.
func NewIdsecIdentityAuthProfilesService(authenticators ...auth.IdsecAuth) (*IdsecIdentityAuthProfilesService, error) {
	identityAuthProfilesService := &IdsecIdentityAuthProfilesService{}
	var identityAuthProfilesServiceInterface services.IdsecService = identityAuthProfilesService
	baseService, err := services.NewIdsecBaseService(identityAuthProfilesServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "", "", "api/idadmin", identityAuthProfilesService.refreshIdentityAuthProfilesAuth)
	if err != nil {
		return nil, err
	}
	client.UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})
	identityAuthProfilesService.client = client
	identityAuthProfilesService.ispAuth = ispAuth
	identityAuthProfilesService.IdsecBaseService = baseService
	return identityAuthProfilesService, nil
}

func (s *IdsecIdentityAuthProfilesService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoPost != nil {
		return s.DoPost
	}
	return s.client.Post
}

func (s *IdsecIdentityAuthProfilesService) refreshIdentityAuthProfilesAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecIdentityAuthProfilesService) parseAuthProfileFromMap(data map[string]interface{}) (*authprofilesmodels.IdsecIdentityAuthProfile, error) {
	type identityAuthProfileStruct struct {
		Uuid              string                 `json:"Uuid"`
		Name              string                 `json:"Name"`
		DurationInMinutes int                    `json:"DurationInMinutes"`
		Challenges        []string               `json:"Challenges"`
		AdditionalData    map[string]interface{} `json:"AdditionalData"`
	}
	var authProfile identityAuthProfileStruct
	authProfileBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(authProfileBytes, &authProfile)
	if err != nil {
		return nil, err
	}
	authProfileModel := &authprofilesmodels.IdsecIdentityAuthProfile{
		AuthProfileID:     authProfile.Uuid,
		AuthProfileName:   authProfile.Name,
		DurationInMinutes: authProfile.DurationInMinutes,
		FirstChallenges:   []string{},
		SecondChallenges:  []string{},
		AdditionalData:    authProfile.AdditionalData,
	}
	if len(authProfile.Challenges) > 0 {
		authProfileModel.FirstChallenges = strings.Split(authProfile.Challenges[0], ",")
	}
	if len(authProfile.Challenges) > 1 {
		authProfileModel.SecondChallenges = strings.Split(authProfile.Challenges[1], ",")
	}
	return authProfileModel, nil
}

// CreateAuthProfile creates a new identity auth profile.
func (s *IdsecIdentityAuthProfilesService) CreateAuthProfile(createAuthProfile *authprofilesmodels.IdsecIdentityCreateAuthProfile) (*authprofilesmodels.IdsecIdentityAuthProfile, error) {
	s.Logger.Debug("Creating identity auth profile")
	createAuthProfileRequest := map[string]interface{}{
		"settings": map[string]interface{}{
			"Name":              createAuthProfile.AuthProfileName,
			"Challenges":        []string{strings.Join(createAuthProfile.FirstChallenges, ",")},
			"DurationInMinutes": createAuthProfile.DurationInMinutes,
		},
	}
	if len(createAuthProfile.SecondChallenges) > 0 {
		createAuthProfileRequest["settings"].(map[string]interface{})["Challenges"] = append(createAuthProfileRequest["settings"].(map[string]interface{})["Challenges"].([]string), strings.Join(createAuthProfile.SecondChallenges, ","))
	}
	if createAuthProfile.AdditionalData != nil {
		createAuthProfileRequest["settings"].(map[string]interface{})["AdditionalData"] = createAuthProfile.AdditionalData
	}
	response, err := s.postOperation()(context.Background(), saveProfileURL, createAuthProfileRequest)
	if err != nil {
		s.Logger.Error("Error creating identity auth profile: %s", err.Error())
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create identity auth profile - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to create identity auth profile - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve created identity auth profile - [%v]", result)
	}
	return s.parseAuthProfileFromMap(result["Result"].(map[string]interface{}))
}

// UpdateAuthProfile updates an existing identity auth profile.
func (s *IdsecIdentityAuthProfilesService) UpdateAuthProfile(updateAuthProfile *authprofilesmodels.IdsecIdentityUpdateAuthProfile) (*authprofilesmodels.IdsecIdentityAuthProfile, error) {
	s.Logger.Debug("Updating identity auth profile with ID [%s]", updateAuthProfile.AuthProfileID)
	existingAuthProfile, err := s.AuthProfile(&authprofilesmodels.IdsecIdentityGetAuthProfile{
		AuthProfileID: updateAuthProfile.AuthProfileID,
	})
	if err != nil {
		return nil, err
	}
	if updateAuthProfile.AuthProfileName != "" {
		existingAuthProfile.AuthProfileName = updateAuthProfile.AuthProfileName
	}
	if len(updateAuthProfile.FirstChallenges) > 0 {
		existingAuthProfile.FirstChallenges = updateAuthProfile.FirstChallenges
	}
	if len(updateAuthProfile.SecondChallenges) > 0 {
		existingAuthProfile.SecondChallenges = updateAuthProfile.SecondChallenges
	}
	if updateAuthProfile.DurationInMinutes > 0 {
		existingAuthProfile.DurationInMinutes = updateAuthProfile.DurationInMinutes
	}
	if updateAuthProfile.AdditionalData != nil {
		existingAuthProfile.AdditionalData = updateAuthProfile.AdditionalData
	}
	updateAuthProfileRequest := map[string]interface{}{
		"settings": map[string]interface{}{
			"Uuid":              existingAuthProfile.AuthProfileID,
			"Name":              existingAuthProfile.AuthProfileName,
			"Challenges":        []string{strings.Join(existingAuthProfile.FirstChallenges, ",")},
			"DurationInMinutes": existingAuthProfile.DurationInMinutes,
		},
	}
	if len(existingAuthProfile.SecondChallenges) > 0 {
		updateAuthProfileRequest["settings"].(map[string]interface{})["Challenges"] = append(updateAuthProfileRequest["settings"].(map[string]interface{})["Challenges"].([]string), strings.Join(existingAuthProfile.SecondChallenges, ","))
	}
	if existingAuthProfile.AdditionalData != nil {
		updateAuthProfileRequest["settings"].(map[string]interface{})["AdditionalData"] = existingAuthProfile.AdditionalData
	}
	response, err := s.postOperation()(context.Background(), saveProfileURL, updateAuthProfileRequest)
	if err != nil {
		s.Logger.Error("Error updating identity auth profile: %s", err.Error())
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update identity auth profile - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to update identity auth profile - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve updated identity auth profile - [%v]", result)
	}
	return s.parseAuthProfileFromMap(result["Result"].(map[string]interface{}))
}

// AuthProfile retrieves an identity auth profile by ID or name.
func (s *IdsecIdentityAuthProfilesService) AuthProfile(getAuthProfile *authprofilesmodels.IdsecIdentityGetAuthProfile) (*authprofilesmodels.IdsecIdentityAuthProfile, error) {
	s.Logger.Debug("Retrieving identity auth profile")
	if getAuthProfile.AuthProfileID == "" && getAuthProfile.AuthProfileName == "" {
		return nil, fmt.Errorf("either AuthProfileID or AuthProfileName must be provided")
	}
	// If AuthProfileName is provided, resolve it to ID
	if getAuthProfile.AuthProfileName != "" && getAuthProfile.AuthProfileID == "" {
		authProfiles, err := s.ListAuthProfilesBy(&authprofilesmodels.IdsecIdentityAuthProfilesFilters{
			AuthProfileName: getAuthProfile.AuthProfileName,
		})
		if err != nil {
			return nil, err
		}
		if len(authProfiles) == 0 {
			return nil, fmt.Errorf("identity auth profile with name [%s] not found", getAuthProfile.AuthProfileName)
		}
		getAuthProfile.AuthProfileID = authProfiles[0].AuthProfileID
	}
	getAuthProfileRequest := map[string]interface{}{
		"Uuid": getAuthProfile.AuthProfileID,
	}
	response, err := s.postOperation()(context.Background(), getProfileURL, getAuthProfileRequest)
	if err != nil {
		s.Logger.Error("Error retrieving identity auth profile: %s", err.Error())
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve identity auth profile - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to retrieve identity auth profile - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve identity auth profile - [%v]", result)
	}
	return s.parseAuthProfileFromMap(result["Result"].(map[string]interface{}))
}

// DeleteAuthProfile deletes an identity auth profile by ID or name.
func (s *IdsecIdentityAuthProfilesService) DeleteAuthProfile(deleteAuthProfile *authprofilesmodels.IdsecIdentityDeleteAuthProfile) error {
	s.Logger.Debug("Deleting identity auth profile with ID [%s]", deleteAuthProfile.AuthProfileID)
	if deleteAuthProfile.AuthProfileID == "" && deleteAuthProfile.AuthProfileName == "" {
		return fmt.Errorf("either AuthProfileID or AuthProfileName must be provided")
	}
	if deleteAuthProfile.AuthProfileName != "" && deleteAuthProfile.AuthProfileID == "" {
		authProfiles, err := s.ListAuthProfilesBy(&authprofilesmodels.IdsecIdentityAuthProfilesFilters{
			AuthProfileName: deleteAuthProfile.AuthProfileName,
		})
		if err != nil {
			return err
		}
		if len(authProfiles) == 0 {
			return fmt.Errorf("identity auth profile with name [%s] not found", deleteAuthProfile.AuthProfileName)
		}
		deleteAuthProfile.AuthProfileID = authProfiles[0].AuthProfileID
	}
	deleteAuthProfileRequest := map[string]interface{}{
		"Uuid": deleteAuthProfile.AuthProfileID,
	}
	response, err := s.postOperation()(context.Background(), deleteProfileURL, deleteAuthProfileRequest)
	if err != nil {
		s.Logger.Error("Error deleting identity auth profile: %s", err.Error())
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete identity auth profile - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return fmt.Errorf("failed to delete identity auth profile - [%v]", result)
	}
	return nil
}

// ListAuthProfiles lists all identity auth profiles.
func (s *IdsecIdentityAuthProfilesService) ListAuthProfiles() ([]*authprofilesmodels.IdsecIdentityAuthProfile, error) {
	s.Logger.Debug("Listing identity auth profiles")
	response, err := s.postOperation()(context.Background(), listProfilesURL, map[string]interface{}{})
	if err != nil {
		s.Logger.Error("Error listing identity auth profiles: %s", err.Error())
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list identity auth profiles - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to list identity auth profiles - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve identity auth profile - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{})["Results"].([]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve identity auth profiles - [%v]", result)
	}
	authProfilesData := result["Result"].(map[string]interface{})["Results"].([]interface{})
	var authProfiles []*authprofilesmodels.IdsecIdentityAuthProfile
	for _, authProfileData := range authProfilesData {
		authProfileMap, ok := authProfileData.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse identity auth profile data - [%v]", authProfileData)
		}
		authProfileMapRow, ok := authProfileMap["Row"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse identity auth profile row data - [%v]", authProfileMap)
		}
		authProfile, err := s.parseAuthProfileFromMap(authProfileMapRow)
		if err != nil {
			return nil, err
		}
		authProfiles = append(authProfiles, authProfile)
	}
	return authProfiles, nil
}

// ListAuthProfilesBy lists identity auth profiles based on provided filters.
func (s *IdsecIdentityAuthProfilesService) ListAuthProfilesBy(filters *authprofilesmodels.IdsecIdentityAuthProfilesFilters) ([]*authprofilesmodels.IdsecIdentityAuthProfile, error) {
	s.Logger.Debug("Listing identity auth profiles by filters")
	allAuthProfiles, err := s.ListAuthProfiles()
	if err != nil {
		return nil, err
	}
	filteredAuthProfiles := []*authprofilesmodels.IdsecIdentityAuthProfile{}
	for _, authProfile := range allAuthProfiles {
		matches := true
		if len(filters.Challenges) > 0 {
			challengeMatch := false
			for _, challenge := range filters.Challenges {
				for _, firstChallenge := range authProfile.FirstChallenges {
					if challenge == firstChallenge {
						challengeMatch = true
						break
					}
				}
				for _, secondChallenge := range authProfile.SecondChallenges {
					if challenge == secondChallenge {
						challengeMatch = true
						break
					}
				}
			}
			if !challengeMatch {
				matches = false
			}
		}
		if filters.AuthProfileName != "" && authProfile.AuthProfileName != filters.AuthProfileName {
			matches = false
		}
		if matches {
			filteredAuthProfiles = append(filteredAuthProfiles, authProfile)
		}
	}
	return filteredAuthProfiles, nil
}

// AuthProfilesStats retrieves statistics related to identity auth profiles.
func (s *IdsecIdentityAuthProfilesService) AuthProfilesStats() (*authprofilesmodels.IdsecIdentityAuthProfilesStats, error) {
	s.Logger.Debug("Retrieving identity auth profiles statistics")
	allAuthProfiles, err := s.ListAuthProfiles()
	if err != nil {
		return nil, err
	}
	stats := &authprofilesmodels.IdsecIdentityAuthProfilesStats{
		AuthProfilesCount: len(allAuthProfiles),
	}
	return stats, nil
}

// ServiceConfig returns the service configuration for the IdsecIdentityAuthProfilesService.
func (s *IdsecIdentityAuthProfilesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
