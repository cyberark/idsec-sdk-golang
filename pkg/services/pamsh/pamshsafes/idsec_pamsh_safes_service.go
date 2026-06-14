package pamshsafes

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	pamshinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/internal"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/models"
)

// Constants for safes URLs
const (
	safesURL       = "/PasswordVault/API/Safes"
	safeURL        = "/PasswordVault/API/Safes/%s/"
	safeMembersURL = "/PasswordVault/API/Safes/%s/Members"
	safeMemberURL  = "/PasswordVault/API/Safes/%s/Members/%s/"
)

type pamshSafesPage = common.IdsecPage[safesmodels.IdsecPamshSafe]

// IdsecPamshSafesService manages PAM self-hosted safes using PVWA-authenticated REST.
type IdsecPamshSafesService struct {
	*services.IdsecBaseService
	*services.IdsecPVWABaseService
}

// NewIdsecPamshSafesService creates a new IdsecPamshSafesService.
func NewIdsecPamshSafesService(authenticators ...auth.IdsecAuth) (*IdsecPamshSafesService, error) {
	pamshSafesService := &IdsecPamshSafesService{}
	var pamshSafesServiceInterface services.IdsecService = pamshSafesService
	baseService, err := services.NewIdsecBaseService(pamshSafesServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	pvwaBaseAuth, err := baseService.Authenticator("pvwa")
	if err != nil {
		return nil, err
	}
	pvwaAuth, ok := pvwaBaseAuth.(*auth.IdsecPVWAAuth)
	if !ok {
		return nil, fmt.Errorf("pamsh-safes: expected IdsecPVWAAuth, got %T", pvwaBaseAuth)
	}
	if pvwaAuth.Token == nil {
		return nil, fmt.Errorf("pamsh-safes: PVWA authenticator has no token; authenticate before constructing the service")
	}

	pamshSafesService.IdsecBaseService = baseService

	pvwaBase, err := services.NewIdsecPVWABaseServiceWithRESTOptions(
		pvwaAuth,
		"pamsh-safes",
		nil,
	)
	if err != nil {
		return nil, err
	}
	pamshSafesService.IdsecPVWABaseService = pvwaBase
	return pamshSafesService, nil
}

func normalizePamshSafeListItem(safeMap map[string]interface{}) {
	if safeID, ok := safeMap["safe_url_id"]; ok {
		safeMap["safe_id"] = safeID
	}
}

func (s *IdsecPamshSafesService) listSafesWithFilters(
	search string,
	sort string,
	offset int,
	limit int,
) (<-chan *pamshSafesPage, <-chan error) {
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
	return pamshinternal.ListPaginated(
		s.PVWAClient(),
		safesURL,
		query,
		pamshinternal.ListPaginatedConfig[safesmodels.IdsecPamshSafe]{
			Logger:       s.Logger,
			ResourceName: "safes",
			ExtractItems: func(resultMap map[string]interface{}) ([]interface{}, error) {
				return pamshinternal.ExtractItemsFromResult(resultMap, "safes", "Safes")
			},
			NormalizeItem: normalizePamshSafeListItem,
		},
	)
}

// Get retrieves a safe by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20Get%20Safes%20Details.htm
func (s *IdsecPamshSafesService) Get(getSafe *safesmodels.IdsecPamshGetSafe) (*safesmodels.IdsecPamshSafe, error) {
	s.Logger.Info("Retrieving safe [%s] - [%s]", getSafe.SafeID, getSafe.SafeName)
	if getSafe.SafeID == "" && getSafe.SafeName == "" {
		return nil, fmt.Errorf("either safe ID or safe name must be provided")
	}
	if getSafe.SafeID == "" && getSafe.SafeName != "" {
		safesPages, errCh := s.listSafesWithFilters(getSafe.SafeName, "", 0, 1)
		safes, err := pamshinternal.DrainPages(safesPages, errCh)
		if err != nil {
			return nil, err
		}
		for _, safe := range safes {
			if safe.SafeName == getSafe.SafeName {
				getSafe.SafeID = safe.SafeID
				break
			}
		}
		if getSafe.SafeID == "" {
			return nil, fmt.Errorf("safe with name '%s' not found", getSafe.SafeName)
		}
	}
	response, err := s.PVWAClient().Get(context.Background(), fmt.Sprintf(safeURL, getSafe.SafeID), nil)
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
	var safe safesmodels.IdsecPamshSafe
	err = mapstructure.Decode(safeJSONMap, &safe)
	if err != nil {
		return nil, err
	}
	return &safe, nil
}

// GetMember retrieves a safe member by its safe ID and member name.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Member.htm
func (s *IdsecPamshSafesService) GetMember(getSafeMember *safesmodels.IdsecPamshGetSafeMember) (*safesmodels.IdsecPamshSafeMember, error) {
	s.Logger.Info("Retrieving safe member [%s] [%s]", getSafeMember.SafeID, getSafeMember.MemberName)
	response, err := s.PVWAClient().Get(context.Background(), fmt.Sprintf(safeMemberURL, getSafeMember.SafeID, getSafeMember.MemberName), nil)
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
	var safeMember safesmodels.IdsecPamshSafeMember
	err = mapstructure.Decode(safeMemberJSON, &safeMember)
	if err != nil {
		return nil, err
	}
	safeMember.PermissionSet = ResolvePermissionSet(safeMember.Permissions)
	return &safeMember, nil
}

// Create adds a new safe.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Safe.htm
func (s *IdsecPamshSafesService) Create(addSafe *safesmodels.IdsecPamshAddSafe) (*safesmodels.IdsecPamshSafe, error) {
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
	response, err := s.PVWAClient().Post(context.Background(), safesURL, addSafeJSON)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusConflict {
		pamshinternal.ClosePVWAResponse(response)
		s.Logger.Info("Safe [%s] already exists, retrieving existing safe", addSafe.SafeName)
		safe, err := s.Get(&safesmodels.IdsecPamshGetSafe{
			SafeName: addSafe.SafeName,
		})
		if err != nil {
			// For some reason, the safe creation returned conflict but the safe is not found when retrieving it
			// So we try again with a post to create
			s.Logger.Info("Safe [%s] not found after conflict, retrying safe creation", addSafe.SafeName)
			response, err = s.PVWAClient().Post(context.Background(), safesURL, addSafeJSON)
			if err != nil {
				return nil, err
			}
		} else {
			return safe, nil
		}
	}
	if response.StatusCode != http.StatusCreated {
		createErr := fmt.Errorf("failed to add safe - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		pamshinternal.ClosePVWAResponse(response)
		return nil, createErr
	}
	safeJSON, err := common.DeserializeJSONSnake(response.Body)
	pamshinternal.ClosePVWAResponse(response)
	if err != nil {
		return nil, err
	}
	safeJSONMap, ok := safeJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to add safe: unexpected response type %T", safeJSON)
	}
	if safeID, ok := safeJSONMap["safe_url_id"]; ok {
		safeJSONMap["safe_id"] = safeID
	}
	var safe safesmodels.IdsecPamshSafe
	err = mapstructure.Decode(safeJSON, &safe)
	if err != nil {
		return nil, err
	}
	return &safe, nil
}

// AddMember adds a new member to a safe.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Safe%20Member.htm
func (s *IdsecPamshSafesService) AddMember(addSafeMember *safesmodels.IdsecPamshAddSafeMember) (*safesmodels.IdsecPamshSafeMember, error) {
	s.Logger.Info("Adding safe member [%s] [%s]", addSafeMember.SafeID, addSafeMember.MemberName)
	if err := PrepareAddMemberPermissions(addSafeMember); err != nil {
		return nil, err
	}
	addSafeMemberJSON, err := common.SerializeJSONCamel(addSafeMember)
	if err != nil {
		return nil, err
	}
	delete(addSafeMemberJSON, "permissionSet")
	delete(addSafeMemberJSON, "safeId")
	response, err := s.PVWAClient().Post(context.Background(), fmt.Sprintf(safeMembersURL, addSafeMember.SafeID), addSafeMemberJSON)
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
	var safeMember safesmodels.IdsecPamshSafeMember
	err = mapstructure.Decode(safeMemberJSON, &safeMember)
	if err != nil {
		return nil, err
	}
	safeMember.PermissionSet = ResolvePermissionSet(safeMember.Permissions)
	return &safeMember, nil
}

// Delete deletes a safe by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Safe.htm
func (s *IdsecPamshSafesService) Delete(deleteSafe *safesmodels.IdsecPamshDeleteSafe) error {
	s.Logger.Info("Deleting safe [%s]", deleteSafe.SafeID)
	response, err := s.PVWAClient().Delete(context.Background(), fmt.Sprintf(safeURL, deleteSafe.SafeID), nil, nil)
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
func (s *IdsecPamshSafesService) DeleteMember(deleteSafeMember *safesmodels.IdsecPamshDeleteSafeMember) error {
	s.Logger.Info("Deleting safe member [%s] [%s]", deleteSafeMember.SafeID, deleteSafeMember.MemberName)
	response, err := s.PVWAClient().Delete(context.Background(), fmt.Sprintf(safeMemberURL, deleteSafeMember.SafeID, deleteSafeMember.MemberName), nil, nil)
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
func (s *IdsecPamshSafesService) Update(updateSafe *safesmodels.IdsecPamshUpdateSafe) (*safesmodels.IdsecPamshSafe, error) {
	s.Logger.Info("Updating safe [%s]", updateSafe.SafeID)
	updateSafeJSON, err := common.SerializeJSONCamel(updateSafe)
	if err != nil {
		return nil, err
	}
	delete(updateSafeJSON, "safeId")
	if len(updateSafeJSON) == 0 {
		return s.Get(&safesmodels.IdsecPamshGetSafe{SafeID: updateSafe.SafeID})
	}
	if _, ok := updateSafeJSON["numberOfDaysRetention"]; ok {
		// If both retention values are set, remove the versions one as only one can be set
		delete(updateSafeJSON, "numberOfVersionsRetention")
	}
	response, err := s.PVWAClient().Put(context.Background(), fmt.Sprintf(safeURL, updateSafe.SafeID), updateSafeJSON)
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
	var safe safesmodels.IdsecPamshSafe
	err = mapstructure.Decode(safeJSON, &safe)
	if err != nil {
		return nil, err
	}
	return &safe, nil
}

// UpdateMember updates a member of a safe by its safe ID and member name.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Update%20Safe%20Member.htm
func (s *IdsecPamshSafesService) UpdateMember(updateSafeMember *safesmodels.IdsecPamshUpdateSafeMember) (*safesmodels.IdsecPamshSafeMember, error) {
	s.Logger.Info("Updating safe member [%s] [%s]", updateSafeMember.SafeID, updateSafeMember.MemberName)
	if err := PrepareUpdateMemberPermissions(updateSafeMember); err != nil {
		return nil, err
	}
	updateSafeMemberJSON, err := common.SerializeJSONCamel(updateSafeMember)
	if err != nil {
		return nil, err
	}
	delete(updateSafeMemberJSON, "safeId")
	delete(updateSafeMemberJSON, "memberName")
	delete(updateSafeMemberJSON, "permissionSet")
	if len(updateSafeMemberJSON) == 0 {
		return s.GetMember(&safesmodels.IdsecPamshGetSafeMember{SafeID: updateSafeMember.SafeID, MemberName: updateSafeMember.MemberName})
	}
	response, err := s.PVWAClient().Put(context.Background(), fmt.Sprintf(safeMemberURL, updateSafeMember.SafeID, updateSafeMember.MemberName), updateSafeMemberJSON)
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
	var safeMember safesmodels.IdsecPamshSafeMember
	err = mapstructure.Decode(safeMemberJSON, &safeMember)
	if err != nil {
		return nil, err
	}
	safeMember.PermissionSet = ResolvePermissionSet(safeMember.Permissions)
	return &safeMember, nil
}

// ServiceConfig returns the service configuration for the IdsecPamshSafesService.
func (s *IdsecPamshSafesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
