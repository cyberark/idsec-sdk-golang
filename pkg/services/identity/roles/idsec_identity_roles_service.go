package roles

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"
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
	addUserToRoleURL         = "SaasManage/AddUsersAndGroupsToRole"
	createRoleURL            = "Roles/StoreRole"
	updateRoleURL            = "Roles/UpdateRole"
	roleMembersURL           = "Roles/GetRoleMembers"
	addAdminRightsToRoleURL  = "SaasManage/AssignSuperRights"
	removeUserFromRoleURL    = "SaasManage/RemoveUsersAndGroupsFromRole"
	deleteRoleURL            = "SaasManage/DeleteRole"
	directoryServiceQueryURL = "UserMgmt/DirectoryServiceQuery"
)

// IdsecIdentityRolesService is the service for managing identity roles.
type IdsecIdentityRolesService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
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
	return identityRolesService, nil
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
	roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{
		RoleName: createRole.RoleName,
	})
	if err == nil && roleID != "" {
		s.Logger.Info("Role already exists with id [%s]", roleID)
		return &rolesmodels.IdsecIdentityRole{
			RoleID:   roleID,
			RoleName: createRole.RoleName,
		}, nil
	}
	createRoleRequest := map[string]interface{}{
		"Name": createRole.RoleName,
	}
	if createRole.Description != "" {
		createRoleRequest["Description"] = createRole.Description
	}
	response, err := s.client.Post(context.Background(), createRoleURL, createRoleRequest)
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
	if !result["success"].(bool) {
		return nil, fmt.Errorf("failed to create role - [%v]", result)
	}
	roleID = result["Result"].(map[string]interface{})["_RowKey"].(string)
	roleDetails := &rolesmodels.IdsecIdentityRole{
		RoleName: createRole.RoleName,
		RoleID:   roleID,
	}
	s.Logger.Info("Role created with id [%s]", roleID)
	if len(createRole.AdminRights) > 0 {
		err = s.AddAdminRightsToRole(&rolesmodels.IdsecIdentityAddAdminRightsToRole{
			RoleID:      roleDetails.RoleID,
			AdminRights: createRole.AdminRights,
		})
		if err != nil {
			return nil, err
		}
	}
	return roleDetails, nil
}

// UpdateRole updates an existing role in the identity service.
func (s *IdsecIdentityRolesService) UpdateRole(updateRole *rolesmodels.IdsecIdentityUpdateRole) error {
	if updateRole.RoleName != "" && updateRole.RoleID == "" {
		roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: updateRole.RoleName})
		if err != nil {
			return fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
		updateRole.RoleID = roleID
	}
	s.Logger.Info("Updating identity role [%s]", updateRole.RoleID)
	updateDict := map[string]interface{}{
		"Name": updateRole.RoleID,
	}
	if updateRole.NewRoleName != "" {
		updateDict["NewName"] = updateRole.NewRoleName
	}
	if updateRole.Description != "" {
		updateDict["Description"] = updateRole.Description
	}
	response, err := s.client.Post(context.Background(), updateRoleURL, updateDict)
	if err != nil {
		return fmt.Errorf("failed to update role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to update role - [%v]", result)
	}
	s.Logger.Info("Role updated successfully")
	return nil
}

// ListRoleMembers retrieves the members of a role in the identity service.
func (s *IdsecIdentityRolesService) ListRoleMembers(listRoleMembers *rolesmodels.IdsecIdentityListRoleMembers) ([]*rolesmodels.IdsecIdentityRoleMember, error) {
	if listRoleMembers.RoleName != "" && listRoleMembers.RoleID == "" {
		roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: listRoleMembers.RoleName})
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
		listRoleMembers.RoleID = roleID
	}
	s.Logger.Info("Listing identity role [%s] members", listRoleMembers.RoleID)
	requestBody := map[string]interface{}{
		"Name": listRoleMembers.RoleID,
	}
	response, err := s.client.Post(context.Background(), roleMembersURL, requestBody)
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
	if !result["success"].(bool) {
		return nil, fmt.Errorf("failed to list role members - [%v]", result)
	}
	var members []*rolesmodels.IdsecIdentityRoleMember
	if resultMap, ok := result["Result"].(map[string]interface{}); ok {
		if results, ok := resultMap["Results"].([]interface{}); ok && len(results) > 0 {
			for _, r := range results {
				row := r.(map[string]interface{})["Row"].(map[string]interface{})
				members = append(members, &rolesmodels.IdsecIdentityRoleMember{
					MemberID:   row["Guid"].(string),
					MemberName: row["Name"].(string),
					MemberType: strings.ToUpper(row["Type"].(string)),
				})
			}
		}
	}
	s.Logger.Info("Listed role members successfully")
	return members, nil
}

// AddAdminRightsToRole adds admin rights to a role in the identity service.
func (s *IdsecIdentityRolesService) AddAdminRightsToRole(addAdminRightsToRole *rolesmodels.IdsecIdentityAddAdminRightsToRole) error {
	s.Logger.Info("Adding admin rights [%v] to role [%s]", addAdminRightsToRole.AdminRights, addAdminRightsToRole.RoleName)

	if addAdminRightsToRole.RoleID == "" && addAdminRightsToRole.RoleName == "" {
		return fmt.Errorf("either role ID or role name must be given")
	}
	var roleID string
	if addAdminRightsToRole.RoleID != "" {
		roleID = addAdminRightsToRole.RoleID
	} else {
		var err error
		roleID, err = s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: addAdminRightsToRole.RoleName})
		if err != nil {
			return fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
	}
	requestBody := make([]map[string]interface{}, len(addAdminRightsToRole.AdminRights))
	for i, adminRight := range addAdminRightsToRole.AdminRights {
		requestBody[i] = map[string]interface{}{
			"Role": roleID,
			"Path": adminRight,
		}
	}
	response, err := s.client.Post(context.Background(), addAdminRightsToRoleURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to add admin rights to role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add admin rights to role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to add admin rights to role - [%v]", result)
	}
	s.Logger.Info("Admin rights added to role successfully")
	return nil
}

// RoleIDByName retrieves the role ID by its name.
func (s *IdsecIdentityRolesService) RoleIDByName(roleIDByName *rolesmodels.IdsecIdentityRoleIDByName) (string, error) {
	s.Logger.Info("Retrieving role ID for name [%s]", roleIDByName.RoleName)
	directoriesService, err := directories.NewIdsecIdentityDirectoriesService(s.ispAuth)
	if err != nil {
		return "", fmt.Errorf("failed to initialize directories service: %v", err)
	}
	foundDirectories, err := directoriesService.ListDirectories(&directoriesmodels.IdsecIdentityListDirectories{
		Directories: []string{identity.Identity},
	})
	if err != nil {
		return "", fmt.Errorf("failed to list directories: %v", err)
	}
	var directoryUUIDs []string
	for _, d := range foundDirectories {
		directoryUUIDs = append(directoryUUIDs, d.DirectoryServiceUUID)
	}
	specificRoleRequest := identity.NewDirectoryServiceQuerySpecificRoleRequest(roleIDByName.RoleName)
	specificRoleRequest.DirectoryServices = directoryUUIDs
	specificRoleRequest.Args = identity.DirectorySearchArgs{Limit: 1}
	var specificRoleRequestBody map[string]interface{}
	err = mapstructure.Decode(specificRoleRequest, &specificRoleRequestBody)
	if err != nil {
		return "", fmt.Errorf("failed to decode specific role request: %v", err)
	}
	response, err := s.client.Post(context.Background(), directoryServiceQueryURL, specificRoleRequestBody)
	if err != nil {
		return "", fmt.Errorf("failed to query directory services role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to query for directory services role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}
	if !result["success"].(bool) {
		return "", fmt.Errorf("failed to query for directory services role - [%v]", result)
	}
	var queryResponse identity.DirectoryServiceQueryResponse
	err = mapstructure.Decode(result, &queryResponse)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}
	allRoles := queryResponse.Result.Roles.Results
	if len(allRoles) == 0 {
		return "", fmt.Errorf("no role found for given name")
	}
	return allRoles[0].Row.ID, nil
}

// AddUserToRole adds a user to a role in the identity service.
func (s *IdsecIdentityRolesService) AddUserToRole(addUserToRole *rolesmodels.IdsecIdentityAddUserToRole) error {
	s.Logger.Info("Adding user [%s] to role [%s]", addUserToRole.Username, addUserToRole.RoleName)
	roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: addUserToRole.RoleName})
	if err != nil {
		return fmt.Errorf("failed to retrieve role ID by name: %v", err)
	}
	requestBody := map[string]interface{}{
		"Name":  roleID,
		"Users": []string{addUserToRole.Username},
	}
	response, err := s.client.Post(context.Background(), addUserToRoleURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to add user to role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add user to role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to add user to role - [%v]", result)
	}
	s.Logger.Info("User added to role successfully")
	return nil
}

// AddGroupToRole adds a group to a role in the identity service.
func (s *IdsecIdentityRolesService) AddGroupToRole(addGroupToRole *rolesmodels.IdsecIdentityAddGroupToRole) error {
	s.Logger.Info("Adding group [%s] to role [%s]", addGroupToRole.GroupName, addGroupToRole.RoleName)
	roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: addGroupToRole.RoleName})
	if err != nil {
		return fmt.Errorf("failed to retrieve role ID by name: %v", err)
	}
	requestBody := map[string]interface{}{
		"Name":   roleID,
		"Groups": []string{addGroupToRole.GroupName},
	}
	response, err := s.client.Post(context.Background(), addUserToRoleURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to add group to role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add group to role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to add group to role - [%v]", result)
	}
	s.Logger.Info("Group added to role successfully")
	return nil
}

// AddRoleToRole adds a role to another role in the identity service.
func (s *IdsecIdentityRolesService) AddRoleToRole(addRoleToRole *rolesmodels.IdsecIdentityAddRoleToRole) error {
	s.Logger.Info("Adding role [%s] to role [%s]", addRoleToRole.RoleNameToAdd, addRoleToRole.RoleName)
	roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: addRoleToRole.RoleName})
	if err != nil {
		return fmt.Errorf("failed to retrieve role ID by name: %v", err)
	}
	requestBody := map[string]interface{}{
		"Name":  roleID,
		"Roles": []string{addRoleToRole.RoleNameToAdd},
	}
	response, err := s.client.Post(context.Background(), addUserToRoleURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to add role to role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add role to role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to add role to role - [%v]", result)
	}
	s.Logger.Info("Role added to role successfully")
	return nil
}

// RemoveUserFromRole removes a user from a role in the identity service.
func (s *IdsecIdentityRolesService) RemoveUserFromRole(removeUserFromRole *rolesmodels.IdsecIdentityRemoveUserFromRole) error {
	s.Logger.Info("Removing user [%s] from role [%s]", removeUserFromRole.Username, removeUserFromRole.RoleName)
	roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: removeUserFromRole.RoleName})
	if err != nil {
		return fmt.Errorf("failed to retrieve role ID by name: %v", err)
	}
	requestBody := map[string]interface{}{
		"Name":  roleID,
		"Users": []string{removeUserFromRole.Username},
	}
	response, err := s.client.Post(context.Background(), removeUserFromRoleURL, requestBody)
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
	if !result["success"].(bool) {
		return fmt.Errorf("failed to remove user from role - [%v]", result)
	}
	s.Logger.Info("User removed from role successfully")
	return nil
}

// RemoveGroupFromRole removes a group from a role in the identity service.
func (s *IdsecIdentityRolesService) RemoveGroupFromRole(removeGroupFromRole *rolesmodels.IdsecIdentityRemoveGroupFromRole) error {
	s.Logger.Info("Removing group [%s] from role [%s]", removeGroupFromRole.GroupName, removeGroupFromRole.RoleName)
	roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: removeGroupFromRole.RoleName})
	if err != nil {
		return fmt.Errorf("failed to retrieve role ID by name: %v", err)
	}
	requestBody := map[string]interface{}{
		"Name":   roleID,
		"Groups": []string{removeGroupFromRole.GroupName},
	}
	response, err := s.client.Post(context.Background(), removeUserFromRoleURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to remove group from role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to remove group from role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to remove group from role - [%v]", result)
	}
	s.Logger.Info("Group removed from role successfully")
	return nil
}

// RemoveRoleFromRole removes a role from another role in the identity service.
func (s *IdsecIdentityRolesService) RemoveRoleFromRole(removeRoleFromRole *rolesmodels.IdsecIdentityRemoveRoleFromRole) error {
	s.Logger.Info("Removing role [%s] from role [%s]", removeRoleFromRole.RoleNameToRemove, removeRoleFromRole.RoleName)
	roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: removeRoleFromRole.RoleName})
	if err != nil {
		return fmt.Errorf("failed to retrieve role ID by name: %v", err)
	}
	requestBody := map[string]interface{}{
		"Name":  roleID,
		"Roles": []string{removeRoleFromRole.RoleNameToRemove},
	}
	response, err := s.client.Post(context.Background(), removeUserFromRoleURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to remove role from role: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to remove role from role - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to remove role from role - [%v]", result)
	}
	s.Logger.Info("Role removed from role successfully")
	return nil
}

// DeleteRole deletes a role in the identity service.
func (s *IdsecIdentityRolesService) DeleteRole(deleteRole *rolesmodels.IdsecIdentityDeleteRole) error {
	s.Logger.Info("Deleting role [%s]", deleteRole.RoleName)
	if deleteRole.RoleName != "" && deleteRole.RoleID == "" {
		roleID, err := s.RoleIDByName(&rolesmodels.IdsecIdentityRoleIDByName{RoleName: deleteRole.RoleName})
		if err != nil {
			return fmt.Errorf("failed to retrieve role ID by name: %v", err)
		}
		deleteRole.RoleID = roleID
	}
	requestBody := map[string]interface{}{
		"Name": deleteRole.RoleID,
	}
	response, err := s.client.Post(context.Background(), deleteRoleURL, requestBody)
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
	if !result["success"].(bool) {
		return fmt.Errorf("failed to delete role - [%v]", result)
	}
	s.Logger.Info("Role deleted successfully")
	return nil
}

// ServiceConfig returns the service configuration for the IdsecIdentityRolesService.
func (s *IdsecIdentityRolesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
