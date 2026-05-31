package roles

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/go-viper/mapstructure/v2"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/identity"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identitycommon "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
)

const (
	addUserToRoleURL             = "SaasManage/AddUsersAndGroupsToRole"
	createRoleURL                = "Roles/StoreRole"
	updateRoleURL                = "Roles/UpdateRole"
	roleMembersURL               = "Roles/GetRoleMembers"
	setDynamicRoleScriptURL      = "Roles/SetDynamicRoleScript"
	addAdminRightsToRoleURL      = "SaasManage/AssignSuperRights"
	removeAdminRightsFromRoleURL = "SaasManage/UnAssignSuperRights"
	removeUserFromRoleURL        = "SaasManage/RemoveUsersAndGroupsFromRole"
	deleteRoleURL                = "SaasManage/DeleteRole"
	directoryServiceQueryURL     = "UserMgmt/DirectoryServiceQuery"
	addRoleAttributesURL         = "RoleAttributes/AddAttributes"
	getRoleAttributesURL         = "RoleAttributes/GetAttributes"
	deleteRoleAttributesURL      = "RoleAttributes/DeleteAttributes"
	updateRoleAttributeURL       = "RoleAttributes/UpdateAttribute"
	getAttributesByRoleURL       = "RoleAttributes/GetRoleAttributes"
	updateAttributesByRoleURL    = "RoleAttributes/UpdateAttributesByRole"
)

const (
	defaultPageSize = 10000
	defaultLimit    = 10000
)

// IdsecIdentityRolesPage is a page of IdsecIdentityRole items.
type IdsecIdentityRolesPage = common.IdsecPage[rolesmodels.IdsecIdentityRole]

// IdsecIdentityRolesService is the service for managing identity roles.
type IdsecIdentityRolesService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
	DirectoriesService *directories.IdsecIdentityDirectoriesService

	DoPost                      func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	DoAdminRightsPost           func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	DoDirectoryServiceQueryPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	DoPostWithParams            func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error)
	DoGet                       func(ctx context.Context, path string, params interface{}) (*http.Response, error)
}

// NewIdsecIdentityRolesService creates a new instance of IdsecIdentityRolesService.
func NewIdsecIdentityRolesService(authenticators ...auth.IdsecAuth) (*IdsecIdentityRolesService, error) {
	identityRolesService := &IdsecIdentityRolesService{}
	var identityRolesServiceInterface services.IdsecService = identityRolesService
	baseService, err := services.NewIdsecBaseService(identityRolesServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	// Create ISP base service which handles client creation
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "", "", "api/idadmin", identityRolesService.refreshIdentityRolesAuth)
	if err != nil {
		return nil, err
	}

	// Update headers for identity service
	ispBaseService.ISPClient().UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})

	// Update identity URL accordingly
	baseURL, err := identitycommon.ResolveIdentityServiceURL(ispAuth, ispBaseService.ISPClient().BaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity service URL: %w", err)
	}
	ispBaseService.ISPClient().BaseURL = baseURL

	identityRolesService.IdsecBaseService = baseService
	identityRolesService.IdsecISPBaseService = ispBaseService
	identityRolesService.DirectoriesService, err = directories.NewIdsecIdentityDirectoriesService(ispAuth)
	if err != nil {
		return nil, err
	}
	return identityRolesService, nil
}

func (s *IdsecIdentityRolesService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoPost != nil {
		return s.DoPost
	}
	return s.ISPClient().Post
}

func (s *IdsecIdentityRolesService) adminRightsPostOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoAdminRightsPost != nil {
		return s.DoAdminRightsPost
	}
	return s.ISPClient().Post
}

func (s *IdsecIdentityRolesService) directoryServiceQueryPostOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoDirectoryServiceQueryPost != nil {
		return s.DoDirectoryServiceQueryPost
	}
	return s.ISPClient().Post
}

func (s *IdsecIdentityRolesService) postWithParamsOperation() func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
	if s.DoPostWithParams != nil {
		return s.DoPostWithParams
	}
	return s.ISPClient().PostWithParams
}

func (s *IdsecIdentityRolesService) getOperation() func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	if s.DoGet != nil {
		return s.DoGet
	}
	return s.ISPClient().Get
}

func (s *IdsecIdentityRolesService) refreshIdentityRolesAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecIdentityRolesService) setRoleDynamicScript(roleID string, script string) error {
	s.Logger.Info("Setting dynamic role script for role [%s]", roleID)
	requestBody := map[string]interface{}{
		"ID":     roleID,
		"Script": script,
	}
	response, err := s.postOperation()(context.Background(), setDynamicRoleScriptURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to set dynamic role script: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to set dynamic role script - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return fmt.Errorf("failed to set dynamic role script - [%v]", result)
	}
	return nil
}

// Create creates a new role in the identity service.
func (s *IdsecIdentityRolesService) Create(createRole *rolesmodels.IdsecIdentityCreateRole) (*rolesmodels.IdsecIdentityRole, error) {
	s.Logger.Info("Trying to create role [%s]", createRole.RoleName)
	role, err := s.Get(&rolesmodels.IdsecIdentityGetRole{
		RoleName: createRole.RoleName,
	})
	if err == nil && role != nil {
		s.Logger.Info("Role already exists with id [%s]", role.RoleID)
		return role, nil
	}
	createRoleRequest := map[string]interface{}{
		"Name": createRole.RoleName,
	}
	if createRole.Description != "" {
		createRoleRequest["Description"] = createRole.Description
	}
	if createRole.RoleType != "" {
		if createRole.RoleType == "Script" && createRole.DynamicRoleScript == "" {
			return nil, fmt.Errorf("dynamic_role_script must be provided when RoleType is Script")
		}
		createRoleRequest["RoleType"] = createRole.RoleType
	} else {
		createRoleRequest["RoleType"] = "PrincipalList"
	}
	response, err := s.postOperation()(context.Background(), createRoleURL, createRoleRequest)
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
		return nil, fmt.Errorf("failed to create role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to create role - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve created role id - [%v]", result)
	}
	roleID, ok := result["Result"].(map[string]interface{})["_RowKey"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve created role id - [%v]", result)
	}
	roleDetails := &rolesmodels.IdsecIdentityRole{
		RoleName: createRole.RoleName,
		RoleID:   roleID,
		RoleType: createRole.RoleType,
	}
	s.Logger.Info("Role created with id [%s]", roleID)
	if createRole.RoleType == "Script" {
		err = s.setRoleDynamicScript(roleID, createRole.DynamicRoleScript)
		if err != nil {
			return nil, fmt.Errorf("failed to set dynamic role script: %v", err)
		}
	}
	if len(createRole.AdminRights) > 0 {
		_, err = s.AddAdminRights(&rolesmodels.IdsecIdentityAddAdminRightsToRole{
			RoleID:      roleDetails.RoleID,
			AdminRights: createRole.AdminRights,
		})
		if err != nil {
			return nil, err
		}
		roleDetails.AdminRights = createRole.AdminRights
	}
	return roleDetails, nil
}

// AddAdminRights adds admin rights to a role in the identity service.
func (s *IdsecIdentityRolesService) AddAdminRights(addAdminRightsToRole *rolesmodels.IdsecIdentityAddAdminRightsToRole) (*rolesmodels.IdsecIdentityRoleAdminRights, error) {
	s.Logger.Info("Adding admin rights [%v] to role [%s]", addAdminRightsToRole.AdminRights, addAdminRightsToRole.RoleName)

	if addAdminRightsToRole.RoleID == "" && addAdminRightsToRole.RoleName == "" {
		return nil, fmt.Errorf("either role ID or role name must be given")
	}
	var roleID string
	if addAdminRightsToRole.RoleID != "" {
		roleID = addAdminRightsToRole.RoleID
	} else {
		var err error
		role, err := s.Get(&rolesmodels.IdsecIdentityGetRole{RoleName: addAdminRightsToRole.RoleName})
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
		roleID = role.RoleID
	}
	requestBody := make([]map[string]interface{}, len(addAdminRightsToRole.AdminRights))
	for i, adminRight := range addAdminRightsToRole.AdminRights {
		requestBody[i] = map[string]interface{}{
			"Role": roleID,
			"Path": adminRight,
		}
	}
	response, err := s.adminRightsPostOperation()(context.Background(), addAdminRightsToRoleURL, requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to add admin rights to role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to add admin rights to role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to add admin rights to role - [%v]", result)
	}
	s.Logger.Info("Admin rights added to role successfully")
	roleAdminRights := &rolesmodels.IdsecIdentityRoleAdminRights{
		RoleID:      roleID,
		AdminRights: addAdminRightsToRole.AdminRights,
	}
	return roleAdminRights, nil
}

// RemoveAdminRights removes admin rights from a role in the identity service.
func (s *IdsecIdentityRolesService) RemoveAdminRights(removeAdminRightsFromRole *rolesmodels.IdsecIdentityRemoveAdminRightsToRole) error {
	s.Logger.Info("Removing admin rights [%v] from role [%s]", removeAdminRightsFromRole.AdminRights, removeAdminRightsFromRole.RoleName)

	if removeAdminRightsFromRole.RoleID == "" && removeAdminRightsFromRole.RoleName == "" {
		return fmt.Errorf("either role ID or role name must be given")
	}
	var roleID string
	if removeAdminRightsFromRole.RoleID != "" {
		roleID = removeAdminRightsFromRole.RoleID
	} else {
		var err error
		role, err := s.Get(&rolesmodels.IdsecIdentityGetRole{RoleName: removeAdminRightsFromRole.RoleName})
		if err != nil {
			return fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
		roleID = role.RoleID
	}
	requestBody := make([]map[string]interface{}, len(removeAdminRightsFromRole.AdminRights))
	for i, adminRight := range removeAdminRightsFromRole.AdminRights {
		requestBody[i] = map[string]interface{}{
			"Role": roleID,
			"Path": adminRight,
		}
	}
	response, err := s.adminRightsPostOperation()(context.Background(), removeAdminRightsFromRoleURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to remove admin rights from role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to remove admin rights from role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return fmt.Errorf("failed to remove admin rights from role - [%v]", result)
	}
	s.Logger.Info("Admin rights removed from role successfully")
	return nil
}

// GetAdminRights retrieves a role's admin rights in the identity service.
func (s *IdsecIdentityRolesService) GetAdminRights(getRoleAdminRights *rolesmodels.IdsecIdentityGetRoleAdminRights) (*rolesmodels.IdsecIdentityRoleAdminRights, error) {
	role, err := s.Get(&rolesmodels.IdsecIdentityGetRole{
		RoleID:   getRoleAdminRights.RoleID,
		RoleName: getRoleAdminRights.RoleName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve role: %v", err)
	}
	roleAdminRights := &rolesmodels.IdsecIdentityRoleAdminRights{
		RoleID:      role.RoleID,
		RoleName:    role.RoleName,
		AdminRights: role.AdminRights,
	}
	return roleAdminRights, nil
}

// Update updates an existing role in the identity service.
func (s *IdsecIdentityRolesService) Update(updateRole *rolesmodels.IdsecIdentityUpdateRole) (*rolesmodels.IdsecIdentityRole, error) {
	if updateRole.RoleName != "" && updateRole.RoleID == "" {
		role, err := s.Get(&rolesmodels.IdsecIdentityGetRole{RoleName: updateRole.RoleName})
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
		updateRole.RoleID = role.RoleID
	}
	s.Logger.Info("Updating identity role [%s]", updateRole.RoleID)
	updateDict := map[string]interface{}{
		"Name": updateRole.RoleID,
	}
	if updateRole.RoleName != "" {
		updateDict["NewName"] = updateRole.RoleName
	}
	if updateRole.Description != "" {
		updateDict["Description"] = updateRole.Description
	}
	response, err := s.postOperation()(context.Background(), updateRoleURL, updateDict)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to update role - [%v]", result)
	}
	s.Logger.Info("Role updated successfully")
	role, err := s.Get(&rolesmodels.IdsecIdentityGetRole{RoleID: updateRole.RoleID})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve updated role: %v", err)
	}
	if role.RoleType == "Script" && updateRole.DynamicRoleScript != "" {
		err = s.setRoleDynamicScript(role.RoleID, updateRole.DynamicRoleScript)
		if err != nil {
			return nil, fmt.Errorf("failed to set dynamic role script: %v", err)
		}
	}
	if len(updateRole.AdminRights) > 0 {
		err = s.RemoveAdminRights(&rolesmodels.IdsecIdentityRemoveAdminRightsToRole{
			RoleID:      updateRole.RoleID,
			AdminRights: updateRole.AdminRights,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to remove admin rights from role: %v", err)
		}
		_, err = s.AddAdminRights(&rolesmodels.IdsecIdentityAddAdminRightsToRole{
			RoleID:      updateRole.RoleID,
			AdminRights: updateRole.AdminRights,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to add admin rights to role: %v", err)
		}
		role.AdminRights = updateRole.AdminRights
	}
	return role, nil
}

// Delete deletes a role in the identity service.
func (s *IdsecIdentityRolesService) Delete(deleteRole *rolesmodels.IdsecIdentityDeleteRole) error {
	s.Logger.Info("Deleting role [%s]", deleteRole.RoleName)
	if deleteRole.RoleName != "" && deleteRole.RoleID == "" {
		role, err := s.Get(&rolesmodels.IdsecIdentityGetRole{RoleName: deleteRole.RoleName})
		if err != nil {
			return fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
		deleteRole.RoleID = role.RoleID
	}
	requestBody := map[string]interface{}{
		"Name": deleteRole.RoleID,
	}
	response, err := s.postOperation()(context.Background(), deleteRoleURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to delete role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return fmt.Errorf("failed to delete role - [%v]", result)
	}
	s.Logger.Info("Role deleted successfully")
	return nil
}

// listRolesBy retrieves roles in the identity service based on a search string.
func (s *IdsecIdentityRolesService) listRolesBy(search string, pageSize int, limit int, maxPageCount int, adminRights []string) (<-chan *IdsecIdentityRolesPage, error) {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	if maxPageCount == 0 {
		maxPageCount = -1
	}

	output := make(chan *IdsecIdentityRolesPage)

	go func() {
		defer close(output)
		foundEntitiesChan, err := s.DirectoriesService.ListEntities(
			&directoriesmodels.IdsecIdentityListDirectoriesEntities{
				Directories:  []string{identity.Identity},
				EntityTypes:  []string{directoriesmodels.EntityTypeRole},
				Search:       search,
				PageSize:     pageSize,
				Limit:        limit,
				MaxPageCount: maxPageCount,
			},
		)
		if err != nil {
			s.Logger.Error("Failed to list directory entities: %v", err)
			return
		}
		for foundEntities := range foundEntitiesChan {
			rolesPage := &IdsecIdentityRolesPage{
				Items: []*rolesmodels.IdsecIdentityRole{},
			}
			for _, entity := range foundEntities.Items {
				if roleEntity, ok := (*entity).(*directoriesmodels.IdsecIdentityRoleEntity); ok {
					role := &rolesmodels.IdsecIdentityRole{
						RoleID:      roleEntity.ID,
						RoleName:    roleEntity.Name,
						Description: roleEntity.Description,
						AdminRights: func() []string {
							var adminRights []string
							for _, right := range roleEntity.AdminRights {
								adminRights = append(adminRights, right.Path)
							}
							return adminRights
						}(),
					}
					if len(adminRights) > 0 {
						matched := false
						for _, adminRight := range adminRights {
							if slices.Contains(role.AdminRights, adminRight) {
								matched = true
								break
							}
						}
						if !matched {
							continue
						}
					}
					rolesPage.Items = append(rolesPage.Items, role)
				}
			}
			output <- rolesPage
		}
	}()

	return output, nil
}

// List retrieves all roles in the identity service.
func (s *IdsecIdentityRolesService) List() (<-chan *IdsecIdentityRolesPage, error) {
	s.Logger.Info("Listing all identity roles")
	return s.listRolesBy("", 0, 0, 0, nil)
}

// ListBy retrieves roles in the identity service based on filters.
func (s *IdsecIdentityRolesService) ListBy(filters *rolesmodels.IdsecIdentityRolesFilter) (<-chan *IdsecIdentityRolesPage, error) {
	s.Logger.Info("Listing identity roles by filters")
	return s.listRolesBy(filters.Search, filters.PageSize, filters.Limit, filters.MaxPageCount, filters.AdminRights)
}

// fetchRoleInfo retrieves the directory-service entry for a role identified by name or ID.
//
// It performs the same DirectoryServiceQuery the public Get method has historically used
// and returns a role populated with the directory-derived fields (ID, Name, Description,
// RoleType, AdminRights). RoleAttributes are intentionally left unset and are merged in
// by the caller from the parallel role-attribute fetch.
func (s *IdsecIdentityRolesService) fetchRoleInfo(searchRoleItem string) (*rolesmodels.IdsecIdentityRole, error) {
	foundDirectories, err := s.DirectoriesService.List(&directoriesmodels.IdsecIdentityListDirectories{
		Directories: []string{identity.Identity},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list directories: %v", err)
	}
	var directoryUUIDs []string
	for _, d := range foundDirectories {
		directoryUUIDs = append(directoryUUIDs, d.DirectoryServiceUUID)
	}
	specificRoleRequest := identity.NewDirectoryServiceQuerySpecificRoleRequest(searchRoleItem)
	specificRoleRequest.DirectoryServices = directoryUUIDs
	specificRoleRequest.Args = identity.DirectorySearchArgs{Limit: 1}
	var specificRoleRequestBody map[string]interface{}
	err = mapstructure.Decode(specificRoleRequest, &specificRoleRequestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to decode specific role request: %v", err)
	}
	response, err := s.directoryServiceQueryPostOperation()(context.Background(), directoryServiceQueryURL, specificRoleRequestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to query directory services role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to query for directory services role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to query for directory services role - [%v]", result)
	}
	var queryResponse identity.DirectoryServiceQueryResponse
	err = mapstructure.Decode(result, &queryResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	allRoles := queryResponse.Result.Roles.Results
	if len(allRoles) == 0 {
		return nil, fmt.Errorf("no role found for given name")
	}
	adminRights := []string{}
	for _, right := range allRoles[0].Row.AdminRights {
		adminRights = append(adminRights, right.Path)
	}
	return &rolesmodels.IdsecIdentityRole{
		RoleID:      allRoles[0].Row.ID,
		RoleName:    allRoles[0].Row.Name,
		Description: allRoles[0].Row.Description,
		RoleType:    allRoles[0].Row.RoleType,
		AdminRights: adminRights,
	}, nil
}

// Get retrieves a specific role in the identity service.
//
// Get returns the directory-derived role info merged with its custom role attribute
// values. When a role ID is supplied, the directory-service query and the role-attribute
// fetch are executed in parallel; when only a role name is supplied the attribute fetch
// waits for the directory query to resolve the role ID first.
func (s *IdsecIdentityRolesService) Get(getRole *rolesmodels.IdsecIdentityGetRole) (*rolesmodels.IdsecIdentityRole, error) {
	if getRole.RoleName == "" && getRole.RoleID == "" {
		return nil, fmt.Errorf("either role ID or role name must be given")
	}
	searchRoleItem := getRole.RoleName
	if getRole.RoleID != "" {
		searchRoleItem = getRole.RoleID
	}
	s.Logger.Info("Retrieving role for [%s]", searchRoleItem)

	type roleInfoResult struct {
		role *rolesmodels.IdsecIdentityRole
		err  error
	}
	type attrsResult struct {
		attributes map[string]string
		err        error
	}

	roleInfoChan := make(chan roleInfoResult, 1)
	go func() {
		role, err := s.fetchRoleInfo(searchRoleItem)
		roleInfoChan <- roleInfoResult{role: role, err: err}
	}()

	// Kick off the role-attribute fetch in parallel only when we already know the role ID.
	// Otherwise we have to wait for the directory query to resolve it first.
	var attrsChan chan attrsResult
	if getRole.RoleID != "" {
		attrsChan = make(chan attrsResult, 1)
		go func() {
			attrs, err := s.GetAttributes(&rolesmodels.IdsecIdentityGetRoleAttributes{RoleID: getRole.RoleID})
			if err != nil {
				attrsChan <- attrsResult{err: err}
				return
			}
			attrsChan <- attrsResult{attributes: attrs.Attributes}
		}()
	}

	roleRes := <-roleInfoChan
	if roleRes.err != nil {
		return nil, roleRes.err
	}
	role := roleRes.role

	if attrsChan == nil {
		// If the directory query did not yield a role ID we cannot fetch attributes; skip
		// the lookup and return the partial role rather than failing the whole call.
		if role.RoleID == "" {
			return role, nil
		}
		attrs, err := s.GetAttributes(&rolesmodels.IdsecIdentityGetRoleAttributes{RoleID: role.RoleID})
		if err != nil {
			// Role attributes are an extension; a tenant without the RoleAttributes endpoints
			// or a transient fetch failure should not block returning the core role info.
			s.Logger.Warning("failed to retrieve role attributes for [%s]: %v", role.RoleID, err)
			return role, nil
		}
		role.RoleAttributes = attrs.Attributes
		return role, nil
	}

	attrsRes := <-attrsChan
	if attrsRes.err != nil {
		s.Logger.Warning("failed to retrieve role attributes for [%s]: %v", role.RoleID, attrsRes.err)
		return role, nil
	}
	role.RoleAttributes = attrsRes.attributes
	return role, nil
}

// Stats retrieves statistics about roles in the identity service.
func (s *IdsecIdentityRolesService) Stats() (*rolesmodels.IdsecIdentityRolesStats, error) {
	s.Logger.Info("Retrieving identity roles statistics")
	roles, err := s.List()
	if err != nil {
		return nil, err
	}

	roleMembersCountByType := make(map[string]int)
	rolesCountByType := make(map[string]int)
	rolesCount := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	// Semaphore to limit concurrent goroutines to 8
	sem := make(chan struct{}, 8)

	for page := range roles {
		for _, role := range page.Items {
			wg.Add(1)
			rolesCount++
			go func(r *rolesmodels.IdsecIdentityRole) {
				defer wg.Done()

				// Acquire semaphore
				sem <- struct{}{}
				defer func() { <-sem }()

				roleMembers, err := s.ListMembers(&rolesmodels.IdsecIdentityListRoleMembers{
					RoleID: r.RoleID,
				})
				if err != nil {
					errOnce.Do(func() {
						firstErr = err
					})
					return
				}

				// Update map in a thread-safe manner
				mu.Lock()
				for _, member := range roleMembers {
					roleMembersCountByType[member.MemberType]++
				}
				if _, ok := rolesCountByType[r.RoleType]; !ok {
					rolesCountByType[r.RoleType] = 0
				}
				rolesCountByType[r.RoleType]++
				mu.Unlock()
			}(role)
		}
	}

	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}

	stats := &rolesmodels.IdsecIdentityRolesStats{
		RolesCount:             rolesCount,
		RoleMembersCountByType: roleMembersCountByType,
		RolesCountByType:       rolesCountByType,
	}
	s.Logger.Info("Retrieved identity roles statistics successfully")
	return stats, nil
}

// GetMember retrieves a specific member of a role in the identity service.
func (s *IdsecIdentityRolesService) GetMember(getRoleMember *rolesmodels.IdsecIdentityGetRoleMember) (*rolesmodels.IdsecIdentityRoleMember, error) {
	if getRoleMember.RoleID == "" {
		return nil, fmt.Errorf("role ID must be given")
	}
	if getRoleMember.MemberID == "" && getRoleMember.MemberName == "" {
		return nil, fmt.Errorf("either member ID or member name must be given")
	}
	s.Logger.Info("Searching for member id [%s] or name [%s] from role [%s]", getRoleMember.MemberID, getRoleMember.MemberName, getRoleMember.RoleID)
	roleMembers, err := s.ListMembers(&rolesmodels.IdsecIdentityListRoleMembers{
		RoleID: getRoleMember.RoleID,
	})
	if err != nil {
		return nil, err
	}
	for _, member := range roleMembers {
		if getRoleMember.MemberID != "" && member.MemberID == getRoleMember.MemberID {
			return member, nil
		}
		lowerCaseMemberName := strings.ToLower(member.MemberName)
		lowerCaseSearchName := strings.ToLower(getRoleMember.MemberName)
		if lowerCaseSearchName != "" && lowerCaseMemberName == lowerCaseSearchName {
			return member, nil
		}
	}
	return nil, fmt.Errorf("member with ID [%s] or name [%s] not found in role [%s]", getRoleMember.MemberID, getRoleMember.MemberName, getRoleMember.RoleID)
}

// ListMembers retrieves the members of a role in the identity service.
func (s *IdsecIdentityRolesService) ListMembers(listRoleMembers *rolesmodels.IdsecIdentityListRoleMembers) ([]*rolesmodels.IdsecIdentityRoleMember, error) {
	if listRoleMembers.RoleName != "" && listRoleMembers.RoleID == "" {
		role, err := s.Get(&rolesmodels.IdsecIdentityGetRole{RoleName: listRoleMembers.RoleName})
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
		listRoleMembers.RoleID = role.RoleID
	}
	s.Logger.Info("Listing identity role [%s] members", listRoleMembers.RoleID)
	requestBody := map[string]interface{}{
		"Name": listRoleMembers.RoleID,
	}
	response, err := s.postOperation()(context.Background(), roleMembersURL, requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to list role members: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list role members - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to list role members - [%v]", result)
	}
	members := []*rolesmodels.IdsecIdentityRoleMember{}
	if resultMap, ok := result["Result"].(map[string]interface{}); ok {
		if results, ok := resultMap["Results"].([]interface{}); ok && len(results) > 0 {
			for _, r := range results {
				row := r.(map[string]interface{})["Row"].(map[string]interface{})
				roleMember := &rolesmodels.IdsecIdentityRoleMember{
					RoleID:     listRoleMembers.RoleID,
					MemberID:   row["Guid"].(string),
					MemberName: row["Name"].(string),
					MemberType: strings.ToUpper(row["Type"].(string)),
				}
				members = append(members, roleMember)
				s.Logger.Info("Listed Role Member [%s] of type [%s] with ID [%s]", roleMember.MemberName, roleMember.MemberType, roleMember.MemberID)
			}
		}
	}
	s.Logger.Info("Listed [%d] role members successfully", len(members))
	return members, nil
}

func (s IdsecIdentityRolesService) ListMembersBy(filters *rolesmodels.IdsecIdentityRoleMembersFilter) ([]*rolesmodels.IdsecIdentityRoleMember, error) {
	s.Logger.Info("Listing identity role members by filters")
	allMembers, err := s.ListMembers(&rolesmodels.IdsecIdentityListRoleMembers{
		RoleID:   filters.RoleID,
		RoleName: filters.RoleName,
	})
	if err != nil {
		return nil, err
	}
	filteredMembers := []*rolesmodels.IdsecIdentityRoleMember{}
	for _, member := range allMembers {
		if filters.MemberTypes != nil {
			for _, memberType := range filters.MemberTypes {
				if member.MemberType == memberType {
					filteredMembers = append(filteredMembers, member)
					break
				}
			}
		} else {
			filteredMembers = append(filteredMembers, member)
		}
	}
	return filteredMembers, nil
}

// AddMember adds a user to a role in the identity service.
func (s *IdsecIdentityRolesService) AddMember(addUserToRole *rolesmodels.IdsecIdentityAddMemberToRole) (*rolesmodels.IdsecIdentityRoleMember, error) {
	s.Logger.Info("Adding user [%s] to role [%s]", addUserToRole.MemberName, addUserToRole.RoleID)
	membersMap := map[string]interface{}{
		"Name": addUserToRole.RoleID,
	}
	switch addUserToRole.MemberType {
	case directoriesmodels.EntityTypeUser:
		if !strings.Contains(addUserToRole.MemberName, "@") {
			tenantSuffix, err := s.DirectoriesService.TenantDefaultSuffix()
			if err != nil {
				return nil, err
			}
			addUserToRole.MemberName = fmt.Sprintf("%s@%s", addUserToRole.MemberName, tenantSuffix)
		}
		membersMap["Users"] = []string{addUserToRole.MemberName}
	case directoriesmodels.EntityTypeGroup:
		membersMap["Groups"] = []string{addUserToRole.MemberName}
	case directoriesmodels.EntityTypeRole:
		membersMap["Roles"] = []string{addUserToRole.MemberName}
	}
	response, err := s.postOperation()(context.Background(), addUserToRoleURL, membersMap)
	if err != nil {
		return nil, fmt.Errorf("failed to add user to role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to add user to role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to add user to role - [%v]", result)
	}
	s.Logger.Info("User added to role successfully")
	return s.GetMember(&rolesmodels.IdsecIdentityGetRoleMember{
		RoleID:     addUserToRole.RoleID,
		MemberName: addUserToRole.MemberName,
	})
}

// RemoveMember removes a user from a role in the identity service.
func (s *IdsecIdentityRolesService) RemoveMember(removeMemberFromRole *rolesmodels.IdsecIdentityRemoveMemberFromRole) error {
	s.Logger.Info("Removing user [%s] from role [%s]", removeMemberFromRole.MemberName, removeMemberFromRole.RoleID)
	membersMap := map[string]interface{}{
		"Name": removeMemberFromRole.RoleID,
	}
	switch removeMemberFromRole.MemberType {
	case directoriesmodels.EntityTypeUser:
		if !strings.Contains(removeMemberFromRole.MemberName, "@") {
			tenantSuffix, err := s.DirectoriesService.TenantDefaultSuffix()
			if err != nil {
				return err
			}
			removeMemberFromRole.MemberName = fmt.Sprintf("%s@%s", removeMemberFromRole.MemberName, tenantSuffix)
		}
		membersMap["Users"] = []string{removeMemberFromRole.MemberName}
	case directoriesmodels.EntityTypeGroup:
		membersMap["Groups"] = []string{removeMemberFromRole.MemberName}
	case directoriesmodels.EntityTypeRole:
		membersMap["Roles"] = []string{removeMemberFromRole.MemberName}
	}

	response, err := s.postOperation()(context.Background(), removeUserFromRoleURL, membersMap)
	if err != nil {
		return fmt.Errorf("failed to remove user from role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to remove user from role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return fmt.Errorf("failed to remove user from role - [%v]", result)
	}
	s.Logger.Info("User removed from role successfully")
	return nil
}

// MemberStats retrieves statistics about members of a specific role in the identity service.
func (s *IdsecIdentityRolesService) MemberStats(getRoleMembersStats *rolesmodels.IdsecIdentityGetRoleMembersStats) (*rolesmodels.IdsecIdentityRoleMembersStats, error) {
	s.Logger.Info("Retrieving identity role members statistics")
	roleMembers, err := s.ListMembers(&rolesmodels.IdsecIdentityListRoleMembers{
		RoleName: getRoleMembersStats.RoleName,
		RoleID:   getRoleMembersStats.RoleID,
	})
	if err != nil {
		return nil, err
	}
	memberCountByType := make(map[string]int)
	for _, member := range roleMembers {
		memberCountByType[member.MemberType]++
	}
	stats := &rolesmodels.IdsecIdentityRoleMembersStats{
		MembersCount:       len(roleMembers),
		MembersCountByType: memberCountByType,
	}
	s.Logger.Info("Retrieved identity role members statistics successfully")
	return stats, nil
}

// AttributesSchema retrieves the role attribute schema columns from the identity service.
//
// AttributesSchema queries the identity service for the current schema columns
// configuration for role attributes. These columns define custom extensible attributes
// that can be added to role objects.
//
// Returns the list of schema columns and any error encountered.
//
// Example:
//
//	schema, err := service.AttributesSchema()
//	if err != nil {
//	    return err
//	}
//	for _, column := range schema.Columns {
//	    fmt.Printf("Column: %s (ID: %s, Type: %s)\n", column.Name, column.ID, column.Type)
//	}
func (s *IdsecIdentityRolesService) AttributesSchema() (*rolesmodels.IdsecIdentityRoleAttributesSchema, error) {
	s.Logger.Info("Getting role attribute schema")
	response, err := s.postOperation()(context.Background(), getRoleAttributesURL, map[string]interface{}{})
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
		return nil, fmt.Errorf("failed to get role attribute schema - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	schemaResponse := &rolesmodels.IdsecIdentityRoleAttributesSchema{
		Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{},
	}
	if attributes, ok := result["Attributes"].([]interface{}); ok {
		for _, attr := range attributes {
			if attrMap, ok := attr.(map[string]interface{}); ok {
				translatedMap := map[string]interface{}{
					"id":          attrMap["ID"],
					"name":        attrMap["Name"],
					"type":        attrMap["Type"],
					"description": attrMap["Description"],
				}
				var schemaColumn rolesmodels.IdsecIdentityRoleAttributesSchemaColumn
				err = mapstructure.Decode(translatedMap, &schemaColumn)
				if err != nil {
					return nil, fmt.Errorf("failed to decode schema column: %w", err)
				}
				schemaResponse.Columns = append(schemaResponse.Columns, schemaColumn)
			}
		}
	}
	if total, ok := result["Total"].(float64); ok {
		schemaResponse.TotalCount = int(total)
	} else {
		schemaResponse.TotalCount = len(schemaResponse.Columns)
	}
	return schemaResponse, nil
}

// addRoleAttributeSchemaColumns posts the AddAttributes payload for the supplied set of
// fresh schema columns. It does not handle name-collision merging; that is the caller's
// responsibility (see CreateAttributesSchema).
func (s *IdsecIdentityRolesService) addRoleAttributeSchemaColumns(columns []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn) error {
	if len(columns) == 0 {
		return nil
	}
	attributes := make([]map[string]interface{}, 0, len(columns))
	for _, col := range columns {
		attributes = append(attributes, map[string]interface{}{
			"Name": col.Name,
			"Type": col.Type,
		})
	}
	addBody := map[string]interface{}{
		"Attributes": attributes,
	}
	response, err := s.postOperation()(context.Background(), addRoleAttributesURL, addBody)
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
		return fmt.Errorf("failed to create role attribute schema - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if res, ok := result["success"].(bool); ok && !res {
		return fmt.Errorf("failed to create role attribute schema - [%v]", result)
	}
	return nil
}

// CreateAttributesSchema creates new role attribute schema columns in the identity service.
//
// CreateAttributesSchema adds new attribute columns to the role schema using the
// RoleAttributes/AddAttributes API. The API only accepts the column Name and Type, so
// any provided Description is applied via the RoleAttributes/UpdateAttribute API after
// the columns are created.
//
// To play nicely with re-runs and partially-applied schemas, columns whose Name already
// exists in the current schema are not re-added; instead, only their Description is
// merged onto the existing column via UpdateAttribute. The Type of an existing column
// is left untouched (the underlying API does not allow changing it).
//
// Parameters:
//   - createSchemaColumns: The request containing the columns to create
//
// Returns the refreshed attribute schema and any error encountered during creation.
//
// Example:
//
//	schema, err := service.CreateAttributesSchema(&rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
//	    Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
//	        {Name: "Department", Type: "Text", Description: "Owning department"},
//	    },
//	})
func (s *IdsecIdentityRolesService) CreateAttributesSchema(createSchemaColumns *rolesmodels.IdsecIdentityCreateRoleAttributesSchema) (*rolesmodels.IdsecIdentityRoleAttributesSchema, error) {
	s.Logger.Info("Creating role attribute schema columns")

	if len(createSchemaColumns.Columns) == 0 {
		return nil, fmt.Errorf("at least one column is required")
	}

	existingSchema, err := s.AttributesSchema()
	if err != nil {
		return nil, fmt.Errorf("failed to get existing schema: %w", err)
	}
	existingByName := make(map[string]rolesmodels.IdsecIdentityRoleAttributesSchemaColumn, len(existingSchema.Columns))
	for _, col := range existingSchema.Columns {
		existingByName[col.Name] = col
	}

	// Partition the requested columns into:
	//   - newColumns:           not present in the schema; created via AddAttributes.
	//   - descriptionUpdates:   columns whose description must be merged via UpdateAttribute,
	//                           either because they already existed by name or because the
	//                           AddAttributes API silently dropped the Description we sent.
	type descriptionUpdate struct {
		attributeID string
		name        string
		description string
	}
	newColumns := make([]rolesmodels.IdsecIdentityRoleAttributesSchemaColumn, 0, len(createSchemaColumns.Columns))
	descriptionUpdates := make([]descriptionUpdate, 0, len(createSchemaColumns.Columns))
	for _, col := range createSchemaColumns.Columns {
		if existing, ok := existingByName[col.Name]; ok {
			s.Logger.Info("Role attribute column [%s] already exists; merging description only", col.Name)
			if col.Description != "" && col.Description != existing.Description {
				descriptionUpdates = append(descriptionUpdates, descriptionUpdate{
					attributeID: existing.ID,
					name:        col.Name,
					description: col.Description,
				})
			}
			continue
		}
		newColumns = append(newColumns, col)
	}

	if err := s.addRoleAttributeSchemaColumns(newColumns); err != nil {
		return nil, err
	}

	// Resolve newly-created column IDs (only if any of them carries a Description that
	// the AddAttributes payload could not deliver) by re-reading the schema.
	pendingNewDescriptions := false
	for _, col := range newColumns {
		if col.Description != "" {
			pendingNewDescriptions = true
			break
		}
	}
	if pendingNewDescriptions {
		refreshedSchema, err := s.AttributesSchema()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve created attribute IDs: %w", err)
		}
		idByName := make(map[string]string, len(refreshedSchema.Columns))
		for _, col := range refreshedSchema.Columns {
			idByName[col.Name] = col.ID
		}
		for _, col := range newColumns {
			if col.Description == "" {
				continue
			}
			id, ok := idByName[col.Name]
			if !ok {
				return nil, fmt.Errorf("created column [%s] not found in refreshed schema", col.Name)
			}
			descriptionUpdates = append(descriptionUpdates, descriptionUpdate{
				attributeID: id,
				name:        col.Name,
				description: col.Description,
			})
		}
	}

	for _, upd := range descriptionUpdates {
		if err := s.updateRoleAttributeDescription(upd.attributeID, upd.description); err != nil {
			return nil, fmt.Errorf("failed to merge description for column [%s]: %w", upd.name, err)
		}
	}

	return s.AttributesSchema()
}

// updateRoleAttributeDescription updates the description of a single role attribute by its ID.
func (s *IdsecIdentityRolesService) updateRoleAttributeDescription(attributeID string, description string) error {
	s.Logger.Info("Updating role attribute schema column [%s]", attributeID)
	requestBody := map[string]interface{}{
		"Description": description,
	}
	params := map[string]string{
		"attributeid": attributeID,
	}
	response, err := s.postWithParamsOperation()(context.Background(), updateRoleAttributeURL, requestBody, params)
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
		return fmt.Errorf("failed to update role attribute - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if res, ok := result["success"].(bool); ok && !res {
		return fmt.Errorf("failed to update role attribute - [%v]", result)
	}
	return nil
}

// UpdateAttributesSchema updates the descriptions of one or more role attribute schema columns.
//
// UpdateAttributesSchema applies description updates via the RoleAttributes/UpdateAttribute
// API. Because the underlying API only supports a single attribute per call, columns are
// updated sequentially. Each column may identify its target attribute by AttributeID or
// by Name (resolved to its ID via the current schema). The first failure aborts the
// remaining updates.
//
// Parameters:
//   - updateSchemaColumns: The request containing the columns to update
//
// Returns the refreshed attribute schema and any error encountered during the update.
//
// Example:
//
//	schema, err := service.UpdateAttributesSchema(&rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
//	    Columns: []rolesmodels.IdsecIdentityUpdateRoleAttributesSchemaColumn{
//	        {Name: "Department", Description: "Role department"},
//	    },
//	})
func (s *IdsecIdentityRolesService) UpdateAttributesSchema(updateSchemaColumns *rolesmodels.IdsecIdentityUpdateRoleAttributesSchema) (*rolesmodels.IdsecIdentityRoleAttributesSchema, error) {
	s.Logger.Info("Updating role attribute schema columns")

	if len(updateSchemaColumns.Columns) == 0 {
		return nil, fmt.Errorf("at least one column is required")
	}
	for i, col := range updateSchemaColumns.Columns {
		if col.ID == "" && col.Name == "" {
			return nil, fmt.Errorf("column at index %d: either attribute_id or name must be provided", i)
		}
	}

	// Resolve any name-based references to attribute IDs in a single pass.
	idByName := map[string]string{}
	needsResolution := false
	for _, col := range updateSchemaColumns.Columns {
		if col.ID == "" {
			needsResolution = true
			break
		}
	}
	if needsResolution {
		existingSchema, err := s.AttributesSchema()
		if err != nil {
			return nil, fmt.Errorf("failed to get existing schema: %w", err)
		}
		for _, c := range existingSchema.Columns {
			idByName[c.Name] = c.ID
		}
	}

	for _, col := range updateSchemaColumns.Columns {
		attributeID := col.ID
		if attributeID == "" {
			id, ok := idByName[col.Name]
			if !ok {
				return nil, fmt.Errorf("attribute with name [%s] not found in role schema", col.Name)
			}
			attributeID = id
		}
		if err := s.updateRoleAttributeDescription(attributeID, col.Description); err != nil {
			return nil, err
		}
	}
	return s.AttributesSchema()
}

// DeleteAttributesSchema deletes role attribute schema columns from the identity service.
//
// DeleteAttributesSchema removes attribute columns from the role schema using the
// RoleAttributes/DeleteAttributes API. Columns may be identified either by their
// attribute IDs (used directly) or by their names (resolved to IDs via the current schema).
//
// Parameters:
//   - deleteSchemaColumns: The request containing the columns to delete
//
// Returns the refreshed attribute schema and any error encountered during deletion.
//
// Example:
//
//	schema, err := service.DeleteAttributesSchema(&rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
//	    ColumnNames: []string{"Department"},
//	})
func (s *IdsecIdentityRolesService) DeleteAttributesSchema(deleteSchemaColumns *rolesmodels.IdsecIdentityDeleteRoleAttributesSchema) (*rolesmodels.IdsecIdentityRoleAttributesSchema, error) {
	s.Logger.Info("Deleting role attribute schema")

	if len(deleteSchemaColumns.IDs) == 0 && len(deleteSchemaColumns.ColumnNames) == 0 && len(deleteSchemaColumns.Columns) == 0 {
		return nil, fmt.Errorf("either ids or column_names or columns must be provided")
	}

	attributeIDs := append([]string{}, deleteSchemaColumns.IDs...)
	columnNames := append([]string{}, deleteSchemaColumns.ColumnNames...)
	for _, col := range deleteSchemaColumns.Columns {
		columnNames = append(columnNames, col.Name)
	}
	if len(columnNames) > 0 {
		existingSchema, err := s.AttributesSchema()
		if err != nil {
			return nil, fmt.Errorf("failed to get existing schema: %w", err)
		}
		idByName := make(map[string]string)
		for _, col := range existingSchema.Columns {
			idByName[col.Name] = col.ID
		}
		for _, name := range columnNames {
			id, ok := idByName[name]
			if !ok {
				return nil, fmt.Errorf("attribute with name [%s] not found in role schema", name)
			}
			if !slices.Contains(attributeIDs, id) {
				attributeIDs = append(attributeIDs, id)
			}
		}
	}

	deleteBody := map[string]interface{}{
		"AttributeIds": attributeIDs,
	}
	response, err := s.postOperation()(context.Background(), deleteRoleAttributesURL, deleteBody)
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
		return nil, fmt.Errorf("failed to delete role attribute schema - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); ok && !res {
		return nil, fmt.Errorf("failed to delete role attribute schema - [%v]", result)
	}
	return s.AttributesSchema()
}

// getRoleAttributeRecords fetches the raw role attribute value records for a role.
//
// The response payload of RoleAttributes/GetRoleAttributes is a flat array of records,
// each record carrying ValueText, ID, _RowKey, AttributeId and RoleId. Some Identity
// deployments wrap the array under the standard {success, Result} envelope, so this
// helper accepts both shapes.
func (s *IdsecIdentityRolesService) getRoleAttributeRecords(roleID string) ([]map[string]interface{}, error) {
	params := map[string]string{
		"roleId": roleID,
	}
	response, err := s.getOperation()(context.Background(), getAttributesByRoleURL, params)
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
		return nil, fmt.Errorf("failed to get role attributes - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var raw interface{}
	err = json.NewDecoder(response.Body).Decode(&raw)
	if err != nil {
		return nil, err
	}
	records := []map[string]interface{}{}
	switch v := raw.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				records = append(records, m)
			}
		}
	case map[string]interface{}:
		if res, ok := v["success"].(bool); ok && !res {
			return nil, fmt.Errorf("failed to get role attributes - [%v]", v)
		}
		var items []interface{}
		switch r := v["Result"].(type) {
		case []interface{}:
			items = r
		case map[string]interface{}:
			if results, ok := r["Results"].([]interface{}); ok {
				items = results
			}
		}
		for _, item := range items {
			if m, ok := item.(map[string]interface{}); ok {
				records = append(records, m)
			}
		}
	}
	return records, nil
}

// buildRoleAttributesUpdateBody constructs the wire payload for RoleAttributes/UpdateAttributesByRole.
//
// The expected shape is:
//
//	{
//	    "RoleId": "<role-id>",
//	    "Attributes": [
//	        {"Id": "<attr-schema-id>", "Name": "<name>", "Type": "<type>", "Description": "<desc>", "Value": "<value>"}
//	    ]
//	}
//
// Each attribute echoes the schema column it refers to and carries the new value. An empty
// Value clears the value for that attribute on the role.
func (s *IdsecIdentityRolesService) buildRoleAttributesUpdateBody(roleID string, schemaColumns []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn, valuesByName map[string]string) (map[string]interface{}, error) {
	columnByName := make(map[string]rolesmodels.IdsecIdentityRoleAttributesSchemaColumn, len(schemaColumns))
	for _, col := range schemaColumns {
		columnByName[col.Name] = col
	}
	attributes := make([]map[string]interface{}, 0, len(valuesByName))
	for name, value := range valuesByName {
		col, ok := columnByName[name]
		if !ok {
			s.Logger.Debug("Attribute [%s] not found in role attribute schema for role [%s]", name, roleID)
			continue
		}
		attributes = append(attributes, map[string]interface{}{
			"Id":          col.ID,
			"Name":        col.Name,
			"Type":        col.Type,
			"Description": col.Description,
			"Value":       value,
		})
	}
	return map[string]interface{}{
		"RoleId":     roleID,
		"Attributes": attributes,
	}, nil
}

// updateAttributesByRole sends an attribute payload to RoleAttributes/UpdateAttributesByRole.
func (s *IdsecIdentityRolesService) updateAttributesByRole(body map[string]interface{}) error {
	if body == nil {
		return nil
	}
	if attributes, ok := body["Attributes"].([]map[string]interface{}); ok && len(attributes) == 0 {
		return nil
	}
	response, err := s.postOperation()(context.Background(), updateAttributesByRoleURL, body)
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
		return fmt.Errorf("failed to update role attributes - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if res, ok := result["success"].(bool); ok && !res {
		return fmt.Errorf("failed to update role attributes - [%v]", result)
	}
	return nil
}

// GetAttributes retrieves attribute values for a given role from the identity service.
//
// GetAttributes fetches role attribute values via RoleAttributes/GetRoleAttributes and
// returns them as a friendly attribute-name → value map. The mapping from internal
// AttributeId references to attribute names is resolved against the current role
// attribute schema.
//
// Parameters:
//   - getRoleAttributes: The request containing the role ID for which to retrieve attributes
//
// Returns the role attributes and any error encountered.
//
// Example:
//
//	attributes, err := service.GetAttributes(&rolesmodels.IdsecIdentityGetRoleAttributes{
//	    RoleID: "role-123",
//	})
//	if err != nil {
//	    return err
//	}
//	for key, value := range attributes.Attributes {
//	    fmt.Printf("Attribute: %s = %v\n", key, value)
//	}
func (s *IdsecIdentityRolesService) GetAttributes(getRoleAttributes *rolesmodels.IdsecIdentityGetRoleAttributes) (*rolesmodels.IdsecIdentityRoleAttributes, error) {
	if getRoleAttributes.RoleID == "" {
		return nil, fmt.Errorf("role_id is required")
	}
	s.Logger.Info("Getting identity role attributes for role [%s]", getRoleAttributes.RoleID)

	records, err := s.getRoleAttributeRecords(getRoleAttributes.RoleID)
	if err != nil {
		return nil, err
	}
	schema, err := s.AttributesSchema()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve role attribute schema: %w", err)
	}
	nameByID := make(map[string]string)
	for _, col := range schema.Columns {
		nameByID[col.ID] = col.Name
	}

	attributes := &rolesmodels.IdsecIdentityRoleAttributes{
		RoleID:     getRoleAttributes.RoleID,
		Attributes: make(map[string]string),
	}
	for _, rec := range records {
		// The endpoint can answer with either of two record shapes depending on the tenant:
		//   - {Id, Name, Type, Description, Value}
		//   - {ID, _RowKey, AttributeId, RoleId, ValueText}
		// The first shape carries the schema column name directly; the second references
		// the schema column by its attribute ID.
		var name string
		if n, ok := rec["Name"].(string); ok && n != "" {
			name = n
		} else if attrID, ok := rec["AttributeId"].(string); ok {
			if mapped, ok := nameByID[attrID]; ok {
				name = mapped
			}
		} else if attrID, ok := rec["Id"].(string); ok {
			if mapped, ok := nameByID[attrID]; ok {
				name = mapped
			}
		}
		if name == "" {
			continue
		}
		var value string
		switch {
		case rec["Value"] != nil:
			if v, ok := rec["Value"].(string); ok {
				value = v
			}
		case rec["ValueText"] != nil:
			if v, ok := rec["ValueText"].(string); ok {
				value = v
			}
		}
		attributes.Attributes[name] = value
	}
	return attributes, nil
}

// UpsertAttributes creates or updates attribute values for a given role in the identity service.
//
// UpsertAttributes resolves attribute names to their schema columns and submits a single
// RoleAttributes/UpdateAttributesByRole call carrying the {Id, Name, Type, Description, Value}
// record for each requested attribute. The API performs the create-or-update logic itself,
// so this method does not need to read existing records first.
//
// Parameters:
//   - upsertRoleAttributes: The request containing the role ID and attributes to upsert
//
// Returns the refreshed role attributes and any error encountered.
//
// Example:
//
//	updated, err := service.UpsertAttributes(&rolesmodels.IdsecIdentityUpsertRoleAttributes{
//	    RoleID: "role-123",
//	    Attributes: map[string]string{
//	        "department": "Engineering",
//	    },
//	})
func (s *IdsecIdentityRolesService) UpsertAttributes(upsertRoleAttributes *rolesmodels.IdsecIdentityUpsertRoleAttributes) (*rolesmodels.IdsecIdentityRoleAttributes, error) {
	if upsertRoleAttributes.RoleID == "" {
		return nil, fmt.Errorf("role_id is required")
	}
	if len(upsertRoleAttributes.Attributes) == 0 {
		return nil, fmt.Errorf("at least one attribute is required")
	}
	s.Logger.Info("Upserting identity role attributes for role [%s]", upsertRoleAttributes.RoleID)

	schema, err := s.AttributesSchema()
	if err != nil {
		return nil, fmt.Errorf("failed to get role attribute schema: %w", err)
	}
	body, err := s.buildRoleAttributesUpdateBody(upsertRoleAttributes.RoleID, schema.Columns, upsertRoleAttributes.Attributes)
	if err != nil {
		return nil, err
	}
	if err := s.updateAttributesByRole(body); err != nil {
		return nil, err
	}
	return s.GetAttributes(&rolesmodels.IdsecIdentityGetRoleAttributes{RoleID: upsertRoleAttributes.RoleID})
}

// DeleteAttributes clears attribute values for a given role in the identity service.
//
// DeleteAttributes sends an empty Value for each requested attribute via
// RoleAttributes/UpdateAttributesByRole. Since the RoleAttributes API only exposes Get
// and UpdateAttributesByRole, removal is expressed as blanking the value. Attributes can
// be referenced by name (via either AttributeNames or the keys of Attributes); names are
// resolved through the current role attribute schema.
//
// Parameters:
//   - deleteRoleAttributes: The request containing the role ID and attribute names to clear
//
// Returns the refreshed role attributes and any error encountered.
//
// Example:
//
//	updated, err := service.DeleteAttributes(&rolesmodels.IdsecIdentityDeleteRoleAttributes{
//	    RoleID:         "role-123",
//	    AttributeNames: []string{"department"},
//	})
func (s *IdsecIdentityRolesService) DeleteAttributes(deleteRoleAttributes *rolesmodels.IdsecIdentityDeleteRoleAttributes) (*rolesmodels.IdsecIdentityRoleAttributes, error) {
	if deleteRoleAttributes.RoleID == "" {
		return nil, fmt.Errorf("role_id is required")
	}
	if len(deleteRoleAttributes.AttributeNames) == 0 && len(deleteRoleAttributes.Attributes) == 0 {
		return nil, fmt.Errorf("at least one attribute name is required")
	}
	s.Logger.Info("Deleting identity role attributes for role [%s]", deleteRoleAttributes.RoleID)

	valuesByName := make(map[string]string, len(deleteRoleAttributes.AttributeNames)+len(deleteRoleAttributes.Attributes))
	for _, name := range deleteRoleAttributes.AttributeNames {
		valuesByName[name] = ""
	}
	for name := range deleteRoleAttributes.Attributes {
		valuesByName[name] = ""
	}

	schema, err := s.AttributesSchema()
	if err != nil {
		return nil, fmt.Errorf("failed to get role attribute schema: %w", err)
	}
	body, err := s.buildRoleAttributesUpdateBody(deleteRoleAttributes.RoleID, schema.Columns, valuesByName)
	if err != nil {
		return nil, err
	}
	if err := s.updateAttributesByRole(body); err != nil {
		return nil, err
	}
	return s.GetAttributes(&rolesmodels.IdsecIdentityGetRoleAttributes{RoleID: deleteRoleAttributes.RoleID})
}

// ServiceConfig returns the service configuration for the IdsecIdentityRolesService.
func (s *IdsecIdentityRolesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
