package safes

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	commonpcloud "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/common"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"

	"io"
	"net/http"
	"net/url"
	"reflect"
	"sync"
)

// Constants for safes URLs
const (
	safesURL       = "/api/safes"
	safeURL        = "/api/safes/%s/"
	safeMembersURL = "/api/safes/%s/members"
	safeMemberURL  = "/api/safes/%s/members/%s/"
)

// SafeMembersPermissionsSets maps permission sets to their corresponding permissions
var SafeMembersPermissionsSets = map[string]safesmodels.IdsecPCloudSafeMemberPermissions{
	safesmodels.ConnectOnly: {
		ListAccounts: true,
		UseAccounts:  true,
	},
	safesmodels.ReadOnly: {
		ListAccounts:     true,
		UseAccounts:      true,
		RetrieveAccounts: true,
	},
	safesmodels.Approver: {
		ListAccounts:                true,
		ViewSafeMembers:             true,
		ManageSafeMembers:           true,
		RequestsAuthorizationLevel1: true,
	},
	safesmodels.AccountsManager: {
		ListAccounts:                           true,
		UseAccounts:                            true,
		RetrieveAccounts:                       true,
		AddAccounts:                            true,
		UpdateAccountProperties:                true,
		UpdateAccountContent:                   true,
		InitiateCPMAccountManagementOperations: true,
		SpecifyNextAccountContent:              true,
		RenameAccounts:                         true,
		DeleteAccounts:                         true,
		UnlockAccounts:                         true,
		ViewSafeMembers:                        true,
		ManageSafeMembers:                      true,
		ViewAuditLog:                           true,
		AccessWithoutConfirmation:              true,
	},
	safesmodels.Full: {
		ListAccounts:                           true,
		UseAccounts:                            true,
		RetrieveAccounts:                       true,
		AddAccounts:                            true,
		UpdateAccountProperties:                true,
		UpdateAccountContent:                   true,
		InitiateCPMAccountManagementOperations: true,
		SpecifyNextAccountContent:              true,
		RenameAccounts:                         true,
		DeleteAccounts:                         true,
		UnlockAccounts:                         true,
		ViewSafeMembers:                        true,
		ManageSafeMembers:                      true,
		ViewAuditLog:                           true,
		AccessWithoutConfirmation:              true,
		RequestsAuthorizationLevel1:            true,
		ManageSafe:                             true,
		BackupSafe:                             true,
		MoveAccountsAndFolders:                 true,
		CreateFolders:                          true,
		DeleteFolders:                          true,
	},
}

// IdsecPCloudSafesPage is a page of IdsecPCloudSafe items.
type IdsecPCloudSafesPage = common.IdsecPage[safesmodels.IdsecPCloudSafe]

// IdsecPCloudSafeMembersPage is a page of IdsecPCloudSafeMember items.
type IdsecPCloudSafeMembersPage = common.IdsecPage[safesmodels.IdsecPCloudSafeMember]

// IdsecPCloudSafesService is the service for managing pCloud Safes.
type IdsecPCloudSafesService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecPCloudSafesService creates a new instance of IdsecPCloudSafesService.
func NewIdsecPCloudSafesService(authenticators ...auth.IdsecAuth) (*IdsecPCloudSafesService, error) {
	pcloudSafesService := &IdsecPCloudSafesService{}
	var pcloudSafesServiceInterface services.IdsecService = pcloudSafesService
	baseService, err := services.NewIdsecBaseService(pcloudSafesServiceInterface, authenticators...)
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
		pcloudSafesService.refreshPCloudSafesAuth,
		commonpcloud.DefaultPCloudRetryStrategy(),
	)
	if err != nil {
		return nil, err
	}

	pcloudSafesService.IdsecBaseService = baseService
	pcloudSafesService.IdsecISPBaseService = ispBaseService
	return pcloudSafesService, nil
}

func (s *IdsecPCloudSafesService) refreshPCloudSafesAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecPCloudSafesService) listSafesWithFilters(
	search string,
	sort string,
	offset int,
	limit int,
) (<-chan *IdsecPCloudSafesPage, error) {
	query := map[string]string{}
	if search != "" {
		query["search"] = search
	}
	if sort != "" {
		query["sort"] = sort
	}
	if offset > 0 {
		query["offset"] = fmt.Sprintf("%d", offset)
	}
	if limit > 0 {
		query["limit"] = fmt.Sprintf("%d", limit)
	}
	results := make(chan *IdsecPCloudSafesPage)
	go func() {
		defer close(results)
		for {
			response, err := s.ISPClient().Get(context.Background(), safesURL, query)
			if err != nil {
				s.Logger.Error("Failed to list safes: %v", err)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to list safes - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
				return
			}
			result, err := common.DeserializeJSONSnake(response.Body)
			if err != nil {
				s.Logger.Error("Failed to decode response: %v", err)
				return
			}
			resultMap := result.(map[string]interface{})
			var safesJSON []interface{}
			if value, ok := resultMap["value"]; ok {
				safesJSON = value.([]interface{})
			} else if safesData, ok := resultMap["Safes"]; ok {
				safesJSON = safesData.([]interface{})
			} else {
				s.Logger.Error("Failed to list safes, unexpected result")
				return
			}
			for i, safe := range safesJSON {
				if safeMap, ok := safe.(map[string]interface{}); ok {
					if safeID, ok := safeMap["safe_url_id"]; ok {
						safesJSON[i].(map[string]interface{})["safe_id"] = safeID
					}
				}
			}
			var safes []*safesmodels.IdsecPCloudSafe
			if err := mapstructure.Decode(safesJSON, &safes); err != nil {
				s.Logger.Error("Failed to validate safes: %v", err)
				return
			}
			results <- &IdsecPCloudSafesPage{Items: safes}
			if nextLink, ok := resultMap["nextLink"].(string); ok {
				nextQuery, _ := url.Parse(nextLink)
				queryValues := nextQuery.Query()
				query = make(map[string]string)
				for key, values := range queryValues {
					if len(values) > 0 {
						query[key] = values[0]
					}
				}
			} else {
				break
			}
		}
	}()
	return results, nil
}

func (s *IdsecPCloudSafesService) listSafeMembersWithFilters(
	safeID string,
	search string,
	sort string,
	offset int,
	limit int,
	memberType string,
) (<-chan *IdsecPCloudSafeMembersPage, error) {
	query := map[string]string{}
	if search != "" {
		query["search"] = search
	}
	if sort != "" {
		query["sort"] = sort
	}
	if offset > 0 {
		query["offset"] = fmt.Sprintf("%d", offset)
	}
	if limit > 0 {
		query["limit"] = fmt.Sprintf("%d", limit)
	}
	if memberType != "" {
		query["filter"] = fmt.Sprintf("memberType eq %s", memberType)
	}
	results := make(chan *IdsecPCloudSafeMembersPage)
	go func() {
		defer close(results)
		for {
			response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(safeMembersURL, safeID), query)
			if err != nil {
				s.Logger.Error("Failed to list safe members: %v", err)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to list safe members - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
				return
			}
			result, err := common.DeserializeJSONSnake(response.Body)
			if err != nil {
				s.Logger.Error("Failed to decode response: %v", err)
				return
			}
			resultMap := result.(map[string]interface{})
			var membersJSON []interface{}
			if value, ok := resultMap["value"]; ok {
				membersJSON = value.([]interface{})
			} else {
				s.Logger.Error("Failed to list safe members, unexpected result")
				return
			}
			for i, safeMember := range membersJSON {
				if safeMemberMap, ok := safeMember.(map[string]interface{}); ok {
					if safeID, ok := safeMemberMap["safe_url_id"]; ok {
						membersJSON[i].(map[string]interface{})["safe_id"] = safeID
					}
				}
			}
			var members []*safesmodels.IdsecPCloudSafeMember
			if err := mapstructure.Decode(membersJSON, &members); err != nil {
				s.Logger.Error("Failed to validate safe members: %v", err)
				return
			}
			for _, member := range members {
				member.PermissionSet = safesmodels.Custom
				for permissionSet, permissions := range SafeMembersPermissionsSets {
					if reflect.DeepEqual(member.Permissions, permissions) {
						member.PermissionSet = permissionSet
						break
					}
				}
			}
			results <- &IdsecPCloudSafeMembersPage{Items: members}
			if nextLink, ok := resultMap["nextLink"].(string); ok {
				nextQuery, _ := url.Parse(nextLink)
				queryValues := nextQuery.Query()
				query = make(map[string]string)
				for key, values := range queryValues {
					if len(values) > 0 {
						query[key] = values[0]
					}
				}
			} else {
				break
			}
		}
	}()
	return results, nil
}

// List returns a channel of IdsecPCloudSafesPage containing all safes.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm?
func (s *IdsecPCloudSafesService) List() (<-chan *IdsecPCloudSafesPage, error) {
	return s.listSafesWithFilters(
		"",
		"",
		0,
		0,
	)
}

// ListBy returns a channel of IdsecPCloudSafesPage containing safes filtered by the given filters.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm?
func (s *IdsecPCloudSafesService) ListBy(safesFilters *safesmodels.IdsecPCloudSafesFilters) (<-chan *IdsecPCloudSafesPage, error) {
	return s.listSafesWithFilters(
		safesFilters.Search,
		safesFilters.Sort,
		safesFilters.Offset,
		safesFilters.Limit,
	)
}

// ListMembers returns a channel of IdsecPCloudSafeMembersPage containing all safe members.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Members.htm
func (s *IdsecPCloudSafesService) ListMembers(listSafeMembers *safesmodels.IdsecPCloudListSafeMembers) (<-chan *IdsecPCloudSafeMembersPage, error) {
	return s.listSafeMembersWithFilters(
		listSafeMembers.SafeID,
		"",
		"",
		0,
		0,
		"",
	)
}

// ListMembersBy returns a channel of IdsecPCloudSafeMembersPage containing safe members filtered by the given filters.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Members.htm
func (s *IdsecPCloudSafesService) ListMembersBy(safeMembersFilters *safesmodels.IdsecPCloudSafeMembersFilters) (<-chan *IdsecPCloudSafeMembersPage, error) {
	return s.listSafeMembersWithFilters(
		safeMembersFilters.SafeID,
		safeMembersFilters.Search,
		safeMembersFilters.Sort,
		safeMembersFilters.Offset,
		safeMembersFilters.Limit,
		safeMembersFilters.MemberType,
	)
}

// Get retrieves a safe by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20Get%20Safes%20Details.htm
func (s *IdsecPCloudSafesService) Get(getSafe *safesmodels.IdsecPCloudGetSafe) (*safesmodels.IdsecPCloudSafe, error) {
	s.Logger.Info("Retrieving safe [%s] - [%s]", getSafe.SafeID, getSafe.SafeName)
	if getSafe.SafeID == "" && getSafe.SafeName == "" {
		return nil, fmt.Errorf("either safe ID or safe name must be provided")
	}
	if getSafe.SafeID == "" && getSafe.SafeName != "" {
		safesPages, err := s.ListBy(&safesmodels.IdsecPCloudSafesFilters{
			Search: getSafe.SafeName,
			Limit:  1,
		})
		if err != nil {
			return nil, err
		}
		for safesPage := range safesPages {
			for _, safe := range safesPage.Items {
				if safe.SafeName == getSafe.SafeName {
					getSafe.SafeID = safe.SafeID
					break
				}
			}
		}
		if getSafe.SafeID == "" {
			return nil, fmt.Errorf("safe with name '%s' not found", getSafe.SafeName)
		}
	}
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(safeURL, getSafe.SafeID), nil)
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
		return nil, fmt.Errorf("failed to retrieve safe - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	safeJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	safeJSONMap := safeJSON.(map[string]interface{})
	if safeID, ok := safeJSONMap["safe_url_id"]; ok {
		safeJSONMap["safe_id"] = safeID
	}
	var safe safesmodels.IdsecPCloudSafe
	err = mapstructure.Decode(safeJSONMap, &safe)
	if err != nil {
		return nil, err
	}
	return &safe, nil
}

// GetMember retrieves a safe member by its safe ID and member name.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Member.htm
func (s *IdsecPCloudSafesService) GetMember(getSafeMember *safesmodels.IdsecPCloudGetSafeMember) (*safesmodels.IdsecPCloudSafeMember, error) {
	s.Logger.Info("Retrieving safe member [%s] [%s]", getSafeMember.SafeID, getSafeMember.MemberName)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(safeMemberURL, getSafeMember.SafeID, getSafeMember.MemberName), nil)
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
		return nil, fmt.Errorf("failed to retrieve safe member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	safeMemberJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	safeMemberJSONMap := safeMemberJSON.(map[string]interface{})
	if safeID, ok := safeMemberJSONMap["safe_url_id"]; ok {
		safeMemberJSONMap["safe_id"] = safeID
	}
	var safeMember safesmodels.IdsecPCloudSafeMember
	err = mapstructure.Decode(safeMemberJSON, &safeMember)
	if err != nil {
		return nil, err
	}
	safeMember.PermissionSet = safesmodels.Custom
	for permissionSet, permissions := range SafeMembersPermissionsSets {
		if reflect.DeepEqual(safeMember.Permissions, permissions) {
			safeMember.PermissionSet = permissionSet
			break
		}
	}
	return &safeMember, nil
}

// Create adds a new safe.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Safe.htm
func (s *IdsecPCloudSafesService) Create(addSafe *safesmodels.IdsecPCloudAddSafe) (*safesmodels.IdsecPCloudSafe, error) {
	s.Logger.Info("Adding safe [%s]", addSafe.SafeName)
	addSafeJSON, err := common.SerializeJSONCamel(addSafe)
	if err != nil {
		return nil, err
	}
	if addSafe.ManagingCPM != "" {
		delete(addSafeJSON, "managingCpm")
		addSafeJSON["managingCPM"] = addSafe.ManagingCPM
	} else {
		addSafeJSON["managingCPM"] = ""
	}
	addSafeJSON["olacEnabled"] = addSafe.OlacEnabled
	// Only one of the retention values needs to be set, default to 0 days if neither is set
	if _, ok := addSafeJSON["numberOfDaysRetention"]; !ok {
		if _, ok := addSafeJSON["numberOfVersionsRetention"]; !ok {
			addSafeJSON["numberOfDaysRetention"] = 0
		}
	} else {
		// If both retention values are set, remove the versions one as only one can be set
		delete(addSafeJSON, "numberOfVersionsRetention")
	}
	response, err := s.ISPClient().Post(context.Background(), safesURL, addSafeJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode == http.StatusConflict {
		s.Logger.Info("Safe [%s] already exists, retrieving existing safe", addSafe.SafeName)
		safe, err := s.Get(&safesmodels.IdsecPCloudGetSafe{
			SafeName: addSafe.SafeName,
		})
		if err != nil {
			// For some reason, the safe creation returned conflict but the safe is not found when retrieving it
			// So we try again with a post to create
			s.Logger.Info("Safe [%s] not found after conflict, retrying safe creation", addSafe.SafeName)
			response, err = s.ISPClient().Post(context.Background(), safesURL, addSafeJSON)
			if err != nil {
				return nil, err
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
		} else {
			return safe, nil
		}
	}
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to add safe - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	safeJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	safeJSONMap := safeJSON.(map[string]interface{})
	if safeID, ok := safeJSONMap["safe_url_id"]; ok {
		safeJSONMap["safe_id"] = safeID
	}
	var safe safesmodels.IdsecPCloudSafe
	err = mapstructure.Decode(safeJSON, &safe)
	if err != nil {
		return nil, err
	}
	return &safe, nil
}

// AddMember adds a new member to a safe.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Safe%20Member.htm
func (s *IdsecPCloudSafesService) AddMember(addSafeMember *safesmodels.IdsecPCloudAddSafeMember) (*safesmodels.IdsecPCloudSafeMember, error) {
	s.Logger.Info("Adding safe member [%s] [%s]", addSafeMember.SafeID, addSafeMember.MemberName)
	if addSafeMember.PermissionSet == "" && addSafeMember.Permissions == nil {
		addSafeMember.PermissionSet = safesmodels.ReadOnly
	}
	if addSafeMember.PermissionSet == safesmodels.Custom && addSafeMember.Permissions == nil {
		return nil, fmt.Errorf("permission set is custom but permissions are not set")
	}
	if addSafeMember.PermissionSet != safesmodels.Custom {
		if permissions, ok := SafeMembersPermissionsSets[addSafeMember.PermissionSet]; ok {
			addSafeMember.Permissions = &permissions
		} else {
			return nil, fmt.Errorf("invalid permission set: %s", addSafeMember.PermissionSet)
		}
	}
	addSafeMemberJSON, err := common.SerializeJSONCamel(addSafeMember)
	if err != nil {
		return nil, err
	}
	delete(addSafeMemberJSON, "permissionSet")
	delete(addSafeMemberJSON, "safeId")
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(safeMembersURL, addSafeMember.SafeID), addSafeMemberJSON)
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
		return nil, fmt.Errorf("failed to add safe member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	safeMemberJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	safeMemberJSONMap := safeMemberJSON.(map[string]interface{})
	if safeID, ok := safeMemberJSONMap["safe_url_id"]; ok {
		safeMemberJSONMap["safe_id"] = safeID
	}
	var safeMember safesmodels.IdsecPCloudSafeMember
	err = mapstructure.Decode(safeMemberJSON, &safeMember)
	if err != nil {
		return nil, err
	}
	safeMember.PermissionSet = safesmodels.Custom
	for permissionSet, permissions := range SafeMembersPermissionsSets {
		if reflect.DeepEqual(safeMember.Permissions, permissions) {
			safeMember.PermissionSet = permissionSet
			break
		}
	}
	return &safeMember, nil
}

// Delete deletes a safe by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Safe.htm
func (s *IdsecPCloudSafesService) Delete(deleteSafe *safesmodels.IdsecPCloudDeleteSafe) error {
	s.Logger.Info("Deleting safe [%s]", deleteSafe.SafeID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(safeURL, deleteSafe.SafeID), nil, nil)
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
		return fmt.Errorf("failed to delete safe - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// DeleteMember deletes a member from a safe by its safe ID and member name.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Safe%20Member.htm
func (s *IdsecPCloudSafesService) DeleteMember(deleteSafeMember *safesmodels.IdsecPCloudDeleteSafeMember) error {
	s.Logger.Info("Deleting safe member [%s] [%s]", deleteSafeMember.SafeID, deleteSafeMember.MemberName)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(safeMemberURL, deleteSafeMember.SafeID, deleteSafeMember.MemberName), nil, nil)
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
		return fmt.Errorf("failed to delete safe member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// Update updates a safe by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Update%20Safe.htm
func (s *IdsecPCloudSafesService) Update(updateSafe *safesmodels.IdsecPCloudUpdateSafe) (*safesmodels.IdsecPCloudSafe, error) {
	s.Logger.Info("Updating safe [%s]", updateSafe.SafeID)
	updateSafeJSON, err := common.SerializeJSONCamel(updateSafe)
	if err != nil {
		return nil, err
	}
	delete(updateSafeJSON, "safeId")
	if len(updateSafeJSON) == 0 {
		return s.Get(&safesmodels.IdsecPCloudGetSafe{SafeID: updateSafe.SafeID})
	}
	if _, ok := updateSafeJSON["numberOfDaysRetention"]; ok {
		// If both retention values are set, remove the versions one as only one can be set
		delete(updateSafeJSON, "numberOfVersionsRetention")
	}
	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(safeURL, updateSafe.SafeID), updateSafeJSON)
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
		return nil, fmt.Errorf("failed to update safe - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	safeJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	safeJSONMap := safeJSON.(map[string]interface{})
	if safeID, ok := safeJSONMap["safe_url_id"]; ok {
		safeJSONMap["safe_id"] = safeID
	}
	var safe safesmodels.IdsecPCloudSafe
	err = mapstructure.Decode(safeJSON, &safe)
	if err != nil {
		return nil, err
	}
	return &safe, nil
}

// UpdateMember updates a member of a safe by its safe ID and member name.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Update%20Safe%20Member.htm
func (s *IdsecPCloudSafesService) UpdateMember(updateSafeMember *safesmodels.IdsecPCloudUpdateSafeMember) (*safesmodels.IdsecPCloudSafeMember, error) {
	s.Logger.Info("Updating safe member [%s] [%s]", updateSafeMember.SafeID, updateSafeMember.MemberName)
	if updateSafeMember.PermissionSet != "" || updateSafeMember.Permissions != nil {
		if updateSafeMember.PermissionSet != safesmodels.Custom {
			if permissions, ok := SafeMembersPermissionsSets[updateSafeMember.PermissionSet]; ok {
				updateSafeMember.Permissions = &permissions
			} else {
				return nil, fmt.Errorf("invalid permission set: %s", updateSafeMember.PermissionSet)
			}
		}
	}
	updateSafeMemberJSON, err := common.SerializeJSONCamel(updateSafeMember)
	if err != nil {
		return nil, err
	}
	delete(updateSafeMemberJSON, "safeId")
	delete(updateSafeMemberJSON, "memberName")
	delete(updateSafeMemberJSON, "permissionSet")
	if len(updateSafeMemberJSON) == 0 {
		return s.GetMember(&safesmodels.IdsecPCloudGetSafeMember{SafeID: updateSafeMember.SafeID, MemberName: updateSafeMember.MemberName})
	}
	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(safeMemberURL, updateSafeMember.SafeID, updateSafeMember.MemberName), updateSafeMemberJSON)
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
		return nil, fmt.Errorf("failed to update safe member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	safeMemberJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	safeMemberJSONMap := safeMemberJSON.(map[string]interface{})
	if safeID, ok := safeMemberJSONMap["safe_url_id"]; ok {
		safeMemberJSONMap["safe_id"] = safeID
	}
	var safeMember safesmodels.IdsecPCloudSafeMember
	err = mapstructure.Decode(safeMemberJSON, &safeMember)
	if err != nil {
		return nil, err
	}
	safeMember.PermissionSet = safesmodels.Custom
	for permissionSet, permissions := range SafeMembersPermissionsSets {
		if reflect.DeepEqual(safeMember.Permissions, permissions) {
			safeMember.PermissionSet = permissionSet
			break
		}
	}
	return &safeMember, nil
}

// Stats retrieves statistics about safes.
func (s *IdsecPCloudSafesService) Stats() (*safesmodels.IdsecPCloudSafesStats, error) {
	s.Logger.Info("Retrieving safes stats")
	safesChan, err := s.List()
	if err != nil {
		return nil, err
	}
	safes := make([]*safesmodels.IdsecPCloudSafe, 0)
	for page := range safesChan {
		safes = append(safes, page.Items...)
	}
	var safesStats safesmodels.IdsecPCloudSafesStats
	safesStats.SafesCount = len(safes)
	safesStats.SafesCountByLocation = make(map[string]int)
	safesStats.SafesCountByCreator = make(map[string]int)
	for _, safe := range safes {
		if _, ok := safesStats.SafesCountByLocation[safe.Location]; !ok {
			safesStats.SafesCountByLocation[safe.Location] = 0
		}
		if _, ok := safesStats.SafesCountByCreator[safe.Creator.Name]; !ok {
			safesStats.SafesCountByCreator[safe.Creator.Name] = 0
		}
		safesStats.SafesCountByLocation[safe.Location]++
		safesStats.SafesCountByCreator[safe.Creator.Name]++
	}
	return &safesStats, nil
}

// MembersStats retrieves statistics about safe members for a specific safe.
func (s *IdsecPCloudSafesService) MembersStats(getSafeMembersStats *safesmodels.IdsecPCloudGetSafeMembersStats) (*safesmodels.IdsecPCloudSafeMembersStats, error) {
	s.Logger.Info("Retrieving safe members stats [%s]", getSafeMembersStats.SafeID)
	safeMembersChan, err := s.ListMembers(&safesmodels.IdsecPCloudListSafeMembers{SafeID: getSafeMembersStats.SafeID})
	if err != nil {
		return nil, err
	}
	safeMembers := make([]*safesmodels.IdsecPCloudSafeMember, 0)
	for page := range safeMembersChan {
		safeMembers = append(safeMembers, page.Items...)
	}
	var safeMembersStats safesmodels.IdsecPCloudSafeMembersStats
	safeMembersStats.SafeMembersCount = len(safeMembers)
	safeMembersStats.SafeMembersPermissionSets = make(map[string]int)
	safeMembersStats.SafeMembersTypesCount = make(map[string]int)
	for _, safeMember := range safeMembers {
		if safeMember.PermissionSet == "" {
			safeMember.PermissionSet = safesmodels.Custom
		}
		if _, ok := safeMembersStats.SafeMembersPermissionSets[safeMember.PermissionSet]; !ok {
			safeMembersStats.SafeMembersPermissionSets[safeMember.PermissionSet] = 0
		}
		if _, ok := safeMembersStats.SafeMembersTypesCount[safeMember.MemberType]; !ok {
			safeMembersStats.SafeMembersTypesCount[safeMember.MemberType] = 0
		}
		safeMembersStats.SafeMembersPermissionSets[safeMember.PermissionSet]++
		safeMembersStats.SafeMembersTypesCount[safeMember.MemberType]++
	}
	return &safeMembersStats, nil
}

// AllMembersStats retrieves statistics about safe members for all safes.
func (s *IdsecPCloudSafesService) AllMembersStats() (*safesmodels.IdsecPCloudSafesMembersStats, error) {
	s.Logger.Info("Retrieving safes members stats")
	safesChan, err := s.List()
	if err != nil {
		return nil, err
	}
	safesMembersStats := make(map[string]safesmodels.IdsecPCloudSafeMembersStats)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var once sync.Once

	for page := range safesChan {
		for _, safe := range page.Items {
			wg.Add(1)
			go func(safe *safesmodels.IdsecPCloudSafe) {
				defer wg.Done()
				safeMembersStats, err := s.MembersStats(&safesmodels.IdsecPCloudGetSafeMembersStats{SafeID: safe.SafeID})
				if err != nil {
					once.Do(func() {
						firstErr = err
					})
					return
				}
				mu.Lock()
				safesMembersStats[safe.SafeName] = *safeMembersStats
				mu.Unlock()
			}(safe)
		}
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return &safesmodels.IdsecPCloudSafesMembersStats{SafeMembersStats: safesMembersStats}, nil
}

// ServiceConfig returns the service configuration for the IdsecPCloudSafesService.
func (s *IdsecPCloudSafesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
