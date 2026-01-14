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
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
)

const (
	addUserToRoleURL             = "SaasManage/AddUsersAndGroupsToRole"
	createRoleURL                = "Roles/StoreRole"
	updateRoleURL                = "Roles/UpdateRole"
	roleMembersURL               = "Roles/GetRoleMembers"
	addAdminRightsToRoleURL      = "SaasManage/AssignSuperRights"
	removeAdminRightsFromRoleURL = "SaasManage/UnAssignSuperRights"
	removeUserFromRoleURL        = "SaasManage/RemoveUsersAndGroupsFromRole"
	deleteRoleURL                = "SaasManage/DeleteRole"
	directoryServiceQueryURL     = "UserMgmt/DirectoryServiceQuery"
)

const (
	defaultPageSize = 10000
	defaultLimit    = 10000
)

// IdsecIdentityRolesPage is a page of IdsecIdentityRole items.
type IdsecIdentityRolesPage = common.IdsecPage[rolesmodels.IdsecIdentityRole]

// IdsecIdentityRolesService is the service for managing identity roles.
type IdsecIdentityRolesService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth            *auth.IdsecISPAuth
	client             *isp.IdsecISPServiceClient
	DirectoriesService *directories.IdsecIdentityDirectoriesService

	DoPost                      func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	DoAdminRightsPost           func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	DoDirectoryServiceQueryPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
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
	client, err := isp.FromISPAuth(ispAuth, "", "", "api/idadmin", identityRolesService.refreshIdentityRolesAuth)
	if err != nil {
		return nil, err
	}
	client.UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})
	identityRolesService.client = client
	identityRolesService.ispAuth = ispAuth
	identityRolesService.IdsecBaseService = baseService
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
	return s.client.Post
}

func (s *IdsecIdentityRolesService) adminRightsPostOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoAdminRightsPost != nil {
		return s.DoAdminRightsPost
	}
	return s.client.Post
}

func (s *IdsecIdentityRolesService) directoryServiceQueryPostOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoDirectoryServiceQueryPost != nil {
		return s.DoDirectoryServiceQueryPost
	}
	return s.client.Post
}

func (s *IdsecIdentityRolesService) refreshIdentityRolesAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// CreateRole creates a new role in the identity service.
func (s *IdsecIdentityRolesService) CreateRole(createRole *rolesmodels.IdsecIdentityCreateRole) (*rolesmodels.IdsecIdentityRole, error) {
	s.Logger.Info("Trying to create role [%s]", createRole.RoleName)
	role, err := s.Role(&rolesmodels.IdsecIdentityGetRole{
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
	}
	s.Logger.Info("Role created with id [%s]", roleID)
	if len(createRole.AdminRights) > 0 {
		_, err = s.AddAdminRightsToRole(&rolesmodels.IdsecIdentityAddAdminRightsToRole{
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

// AddAdminRightsToRole adds admin rights to a role in the identity service.
func (s *IdsecIdentityRolesService) AddAdminRightsToRole(addAdminRightsToRole *rolesmodels.IdsecIdentityAddAdminRightsToRole) (*rolesmodels.IdsecIdentityRoleAdminRights, error) {
	s.Logger.Info("Adding admin rights [%v] to role [%s]", addAdminRightsToRole.AdminRights, addAdminRightsToRole.RoleName)

	if addAdminRightsToRole.RoleID == "" && addAdminRightsToRole.RoleName == "" {
		return nil, fmt.Errorf("either role ID or role name must be given")
	}
	var roleID string
	if addAdminRightsToRole.RoleID != "" {
		roleID = addAdminRightsToRole.RoleID
	} else {
		var err error
		role, err := s.Role(&rolesmodels.IdsecIdentityGetRole{RoleName: addAdminRightsToRole.RoleName})
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
	return &rolesmodels.IdsecIdentityRoleAdminRights{
		RoleID:      roleID,
		AdminRights: addAdminRightsToRole.AdminRights,
	}, nil
}

// RemoveAdminRightsFromRole removes admin rights from a role in the identity service.
func (s *IdsecIdentityRolesService) RemoveAdminRightsFromRole(removeAdminRightsFromRole *rolesmodels.IdsecIdentityRemoveAdminRightsToRole) error {
	s.Logger.Info("Removing admin rights [%v] from role [%s]", removeAdminRightsFromRole.AdminRights, removeAdminRightsFromRole.RoleName)

	if removeAdminRightsFromRole.RoleID == "" && removeAdminRightsFromRole.RoleName == "" {
		return fmt.Errorf("either role ID or role name must be given")
	}
	var roleID string
	if removeAdminRightsFromRole.RoleID != "" {
		roleID = removeAdminRightsFromRole.RoleID
	} else {
		var err error
		role, err := s.Role(&rolesmodels.IdsecIdentityGetRole{RoleName: removeAdminRightsFromRole.RoleName})
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

// RoleAdminRights retrieves a role's admin rights in the identity service.
func (s *IdsecIdentityRolesService) RoleAdminRights(getRoleAdminRights *rolesmodels.IdsecIdentityGetRoleAdminRights) (*rolesmodels.IdsecIdentityRoleAdminRights, error) {
	role, err := s.Role(&rolesmodels.IdsecIdentityGetRole{
		RoleID:   getRoleAdminRights.RoleID,
		RoleName: getRoleAdminRights.RoleName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve role: %v", err)
	}
	return &rolesmodels.IdsecIdentityRoleAdminRights{
		RoleID:      role.RoleID,
		RoleName:    role.RoleName,
		AdminRights: role.AdminRights,
	}, nil
}

// UpdateRole updates an existing role in the identity service.
func (s *IdsecIdentityRolesService) UpdateRole(updateRole *rolesmodels.IdsecIdentityUpdateRole) (*rolesmodels.IdsecIdentityRole, error) {
	if updateRole.RoleName != "" && updateRole.RoleID == "" {
		role, err := s.Role(&rolesmodels.IdsecIdentityGetRole{RoleName: updateRole.RoleName})
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
	role, err := s.Role(&rolesmodels.IdsecIdentityGetRole{RoleID: updateRole.RoleID})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve updated role: %v", err)
	}
	if len(updateRole.AdminRights) > 0 {
		err = s.RemoveAdminRightsFromRole(&rolesmodels.IdsecIdentityRemoveAdminRightsToRole{
			RoleID:      updateRole.RoleID,
			AdminRights: updateRole.AdminRights,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to remove admin rights from role: %v", err)
		}
		_, err = s.AddAdminRightsToRole(&rolesmodels.IdsecIdentityAddAdminRightsToRole{
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

// DeleteRole deletes a role in the identity service.
func (s *IdsecIdentityRolesService) DeleteRole(deleteRole *rolesmodels.IdsecIdentityDeleteRole) error {
	s.Logger.Info("Deleting role [%s]", deleteRole.RoleName)
	if deleteRole.RoleName != "" && deleteRole.RoleID == "" {
		role, err := s.Role(&rolesmodels.IdsecIdentityGetRole{RoleName: deleteRole.RoleName})
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
		foundEntitiesChan, err := s.DirectoriesService.ListDirectoriesEntities(
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

// ListRoles retrieves all roles in the identity service.
func (s *IdsecIdentityRolesService) ListRoles() (<-chan *IdsecIdentityRolesPage, error) {
	s.Logger.Info("Listing all identity roles")
	return s.listRolesBy("", 0, 0, 0, nil)
}

// ListRolesBy retrieves roles in the identity service based on filters.
func (s *IdsecIdentityRolesService) ListRolesBy(filters *rolesmodels.IdsecIdentityRolesFilter) (<-chan *IdsecIdentityRolesPage, error) {
	s.Logger.Info("Listing identity roles by filters")
	return s.listRolesBy(filters.Search, filters.PageSize, filters.Limit, filters.MaxPageCount, filters.AdminRights)
}

// Role retrieves a specific role in the identity service.
func (s *IdsecIdentityRolesService) Role(getRole *rolesmodels.IdsecIdentityGetRole) (*rolesmodels.IdsecIdentityRole, error) {
	if getRole.RoleName == "" && getRole.RoleID == "" {
		return nil, fmt.Errorf("either role ID or role name must be given")
	}
	searchRoleItem := getRole.RoleName
	if getRole.RoleID != "" {
		searchRoleItem = getRole.RoleID
	}
	s.Logger.Info("Retrieving role ID for name [%s]", searchRoleItem)
	foundDirectories, err := s.DirectoriesService.ListDirectories(&directoriesmodels.IdsecIdentityListDirectories{
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
	return &rolesmodels.IdsecIdentityRole{
		RoleID:      allRoles[0].Row.ID,
		RoleName:    allRoles[0].Row.Name,
		Description: allRoles[0].Row.Description,
		AdminRights: func() []string {
			var adminRights []string
			for _, right := range allRoles[0].Row.AdminRights {
				adminRights = append(adminRights, right.Path)
			}
			return adminRights
		}(),
	}, nil
}

// RolesStats retrieves statistics about roles in the identity service.
func (s *IdsecIdentityRolesService) RolesStats() (*rolesmodels.IdsecIdentityRolesStats, error) {
	s.Logger.Info("Retrieving identity roles statistics")
	roles, err := s.ListRoles()
	if err != nil {
		return nil, err
	}

	roleMembersCountByType := make(map[string]int)
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

				roleMembers, err := s.ListRoleMembers(&rolesmodels.IdsecIdentityListRoleMembers{
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
	}
	s.Logger.Info("Retrieved identity roles statistics successfully")
	return stats, nil
}

// RoleMember retrieves a specific member of a role in the identity service.
func (s *IdsecIdentityRolesService) RoleMember(getRoleMember *rolesmodels.IdsecIdentityGetRoleMember) (*rolesmodels.IdsecIdentityRoleMember, error) {
	if getRoleMember.RoleID == "" {
		return nil, fmt.Errorf("role ID must be given")
	}
	if getRoleMember.MemberID == "" && getRoleMember.MemberName == "" {
		return nil, fmt.Errorf("either member ID or member name must be given")
	}
	s.Logger.Info("Searching for member id [%s] or name [%s] from role [%s]", getRoleMember.MemberID, getRoleMember.MemberName, getRoleMember.RoleID)
	roleMembers, err := s.ListRoleMembers(&rolesmodels.IdsecIdentityListRoleMembers{
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

// ListRoleMembers retrieves the members of a role in the identity service.
func (s *IdsecIdentityRolesService) ListRoleMembers(listRoleMembers *rolesmodels.IdsecIdentityListRoleMembers) ([]*rolesmodels.IdsecIdentityRoleMember, error) {
	if listRoleMembers.RoleName != "" && listRoleMembers.RoleID == "" {
		role, err := s.Role(&rolesmodels.IdsecIdentityGetRole{RoleName: listRoleMembers.RoleName})
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

func (s IdsecIdentityRolesService) ListRoleMembersBy(filters *rolesmodels.IdsecIdentityRoleMembersFilter) ([]*rolesmodels.IdsecIdentityRoleMember, error) {
	s.Logger.Info("Listing identity role members by filters")
	allMembers, err := s.ListRoleMembers(&rolesmodels.IdsecIdentityListRoleMembers{
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

// AddUserToRole adds a user to a role in the identity service.
func (s *IdsecIdentityRolesService) AddMemberToRole(addUserToRole *rolesmodels.IdsecIdentityAddMemberToRole) (*rolesmodels.IdsecIdentityRoleMember, error) {
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
	return s.RoleMember(&rolesmodels.IdsecIdentityGetRoleMember{
		RoleID:     addUserToRole.RoleID,
		MemberName: addUserToRole.MemberName,
	})
}

// RemoveUserFromRole removes a user from a role in the identity service.
func (s *IdsecIdentityRolesService) RemoveMemberFromRole(removeMemberFromRole *rolesmodels.IdsecIdentityRemoveMemberFromRole) error {
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

// RoleMembersStats retrieves statistics about members of a specific role in the identity service.
func (s *IdsecIdentityRolesService) RoleMembersStats(getRoleMembersStats *rolesmodels.IdsecIdentityGetRoleMembersStats) (*rolesmodels.IdsecIdentityRoleMembersStats, error) {
	s.Logger.Info("Retrieving identity role members statistics")
	roleMembers, err := s.ListRoleMembers(&rolesmodels.IdsecIdentityListRoleMembers{
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

// ServiceConfig returns the service configuration for the IdsecIdentityRolesService.
func (s *IdsecIdentityRolesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
