// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package usergroups

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	commonpcloud "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/common"
	usergroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/usergroups/models"
)

const (
	userGroupsURL       = "/PasswordVault/API/UserGroups"
	userGroupURL        = "/PasswordVault/API/UserGroups/%d"
	userGroupMembersURL = "/PasswordVault/API/UserGroups/%d/Members"
	userGroupMemberURL  = "/PasswordVault/API/UserGroups/%d/Members/%s"
)

// IdsecPCloudUserGroupsPage is a page of Vault user groups returned by the list operations.
type IdsecPCloudUserGroupsPage = common.IdsecPage[usergroupsmodels.IdsecPCloudUserGroup]

// IdsecPCloudUserGroupsService manages Vault user groups and their memberships via the PVWA REST API.
type IdsecPCloudUserGroupsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecPCloudUserGroupsService creates a new instance of IdsecPCloudUserGroupsService.
func NewIdsecPCloudUserGroupsService(authenticators ...auth.IdsecAuth) (*IdsecPCloudUserGroupsService, error) {
	svc := &IdsecPCloudUserGroupsService{}
	var svcInterface services.IdsecService = svc
	baseService, err := services.NewIdsecBaseService(svcInterface, authenticators...)
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
		"",
		svc.refreshAuth,
		commonpcloud.DefaultPCloudRetryStrategy(),
	)
	if err != nil {
		return nil, err
	}

	svc.IdsecBaseService = baseService
	svc.IdsecISPBaseService = ispBaseService
	return svc, nil
}

func (s *IdsecPCloudUserGroupsService) refreshAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// normalizeUserGroupItemMap renames the API's "id" key to "group_id" so a group decodes into
// the same identifier the member models use.
func normalizeUserGroupItemMap(userGroupMap map[string]interface{}) {
	if id, ok := userGroupMap["id"]; ok {
		userGroupMap["group_id"] = id
	}
}

func (s *IdsecPCloudUserGroupsService) parseUserGroupResponse(responseBody io.ReadCloser) (*usergroupsmodels.IdsecPCloudUserGroup, error) {
	userGroupJSON, err := common.DeserializeJSONSnake(responseBody)
	if err != nil {
		return nil, err
	}
	userGroupJSONMap, ok := userGroupJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid user group response format")
	}
	normalizeUserGroupItemMap(userGroupJSONMap)
	var userGroup usergroupsmodels.IdsecPCloudUserGroup
	if err := mapstructure.Decode(userGroupJSONMap, &userGroup); err != nil {
		return nil, err
	}
	return &userGroup, nil
}

// decodeUserGroupsFromResultMap decodes one page of the user groups list response, accepting
// either the OData-style "value" key or the legacy "UserGroups" key.
func decodeUserGroupsFromResultMap(resultMap map[string]interface{}) ([]*usergroupsmodels.IdsecPCloudUserGroup, error) {
	userGroupsJSON, err := pagination.ExtractItemsFromResult(resultMap, "user groups", "UserGroups")
	if err != nil {
		return nil, err
	}
	for _, userGroup := range userGroupsJSON {
		if userGroupMap, ok := userGroup.(map[string]interface{}); ok {
			normalizeUserGroupItemMap(userGroupMap)
		}
	}
	var userGroups []*usergroupsmodels.IdsecPCloudUserGroup
	if err := mapstructure.Decode(userGroupsJSON, &userGroups); err != nil {
		return nil, fmt.Errorf("failed to validate user groups: %w", err)
	}
	return userGroups, nil
}

func (s *IdsecPCloudUserGroupsService) listUserGroupsWithFilters(
	ctx context.Context,
	userGroupsFilters *usergroupsmodels.IdsecPCloudUserGroupsFilters,
) (<-chan *IdsecPCloudUserGroupsPage, error) {
	initialQuery := map[string]string{}
	if userGroupsFilters != nil {
		if userGroupsFilters.Search != "" {
			initialQuery["search"] = userGroupsFilters.Search
		}
		if userGroupsFilters.GroupType != "" {
			initialQuery["filter"] = fmt.Sprintf("groupType eq %s", userGroupsFilters.GroupType)
		}
		if userGroupsFilters.IncludePredefinedUsers {
			initialQuery["includePredefinedUsers"] = "true"
		}
		if userGroupsFilters.Sort != "" {
			initialQuery["sort"] = userGroupsFilters.Sort
		}
		if userGroupsFilters.Offset > 0 {
			initialQuery["offset"] = fmt.Sprintf("%d", userGroupsFilters.Offset)
		}
		if userGroupsFilters.Limit > 0 {
			initialQuery["limit"] = fmt.Sprintf("%d", userGroupsFilters.Limit)
		}
	}
	return pagination.ListAllPaginated[usergroupsmodels.IdsecPCloudUserGroup](
		ctx,
		pagination.HTTPGetFetch(s.ISPClient(), userGroupsURL, initialQuery),
		pagination.ListPaginatedConfig[usergroupsmodels.IdsecPCloudUserGroup]{
			ResourceName: "user groups",
			Decode:       decodeUserGroupsFromResultMap,
		},
	)
}

// List returns a channel of IdsecPCloudUserGroupsPage containing all Vault user groups.
// On failure, returns a non-nil error and a nil channel.
func (s *IdsecPCloudUserGroupsService) List() (<-chan *IdsecPCloudUserGroupsPage, error) {
	return s.ListContext(context.Background())
}

// ListContext is like List but accepts a context.Context.
func (s *IdsecPCloudUserGroupsService) ListContext(ctx context.Context) (<-chan *IdsecPCloudUserGroupsPage, error) {
	return s.listUserGroupsWithFilters(ctx, nil)
}

// ListBy returns a channel of IdsecPCloudUserGroupsPage containing the Vault user groups
// matching the given filters.
func (s *IdsecPCloudUserGroupsService) ListBy(userGroupsFilters *usergroupsmodels.IdsecPCloudUserGroupsFilters) (<-chan *IdsecPCloudUserGroupsPage, error) {
	return s.ListByContext(context.Background(), userGroupsFilters)
}

// ListByContext is like ListBy but accepts a context.Context.
func (s *IdsecPCloudUserGroupsService) ListByContext(
	ctx context.Context,
	userGroupsFilters *usergroupsmodels.IdsecPCloudUserGroupsFilters,
) (<-chan *IdsecPCloudUserGroupsPage, error) {
	return s.listUserGroupsWithFilters(ctx, userGroupsFilters)
}

// Create adds a new Vault user group via POST /PasswordVault/API/UserGroups.
func (s *IdsecPCloudUserGroupsService) Create(addUserGroup *usergroupsmodels.IdsecPCloudAddUserGroup) (*usergroupsmodels.IdsecPCloudUserGroup, error) {
	s.Logger.Info("Creating pCloud user group [%s] in location [%s]", addUserGroup.GroupName, addUserGroup.Location)

	addUserGroupJSON, err := common.SerializeJSONCamel(addUserGroup)
	if err != nil {
		return nil, err
	}

	response, err := s.ISPClient().Post(context.Background(), userGroupsURL, addUserGroupJSON)
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
		return nil, fmt.Errorf("failed to create user group - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	userGroup, err := s.parseUserGroupResponse(response.Body)
	if err != nil {
		return nil, err
	}
	// Not every PVWA version echoes the new group's ID back, and the ID is what Delete and the
	// terraform import addressing key on. The POST succeeded, so the group exists: resolve it
	// by name rather than handing back a group whose identifier is 0.
	if userGroup.GroupID == 0 {
		s.Logger.Info("Created user group [%s] came back without an ID, resolving it by name", addUserGroup.GroupName)
		return s.Get(&usergroupsmodels.IdsecPCloudGetUserGroup{GroupName: addUserGroup.GroupName})
	}
	return userGroup, nil
}

// Get retrieves a single Vault user group by name, by numeric ID, or by both.
//
// PVWA has no per-version-stable GET /PasswordVault/API/UserGroups/{id}, so the group is
// resolved through the list endpoint: the name, when given, narrows the server-side search,
// and the returned page is then matched on the ID when one was supplied. Group names are
// matched case-insensitively because the Vault treats them that way.
func (s *IdsecPCloudUserGroupsService) Get(getUserGroup *usergroupsmodels.IdsecPCloudGetUserGroup) (*usergroupsmodels.IdsecPCloudUserGroup, error) {
	s.Logger.Info("Retrieving pCloud user group [%d] - [%s]", getUserGroup.GroupID, getUserGroup.GroupName)
	if getUserGroup.GroupID == 0 && getUserGroup.GroupName == "" {
		return nil, fmt.Errorf("either user group ID or user group name must be provided")
	}

	userGroupsPages, err := s.ListBy(&usergroupsmodels.IdsecPCloudUserGroupsFilters{
		Search:                 getUserGroup.GroupName,
		IncludePredefinedUsers: true,
	})
	if err != nil {
		return nil, err
	}
	for userGroupsPage := range userGroupsPages {
		for _, userGroup := range userGroupsPage.Items {
			if getUserGroup.GroupID != 0 && userGroup.GroupID != getUserGroup.GroupID {
				continue
			}
			if getUserGroup.GroupName != "" && !strings.EqualFold(userGroup.GroupName, getUserGroup.GroupName) {
				continue
			}
			return userGroup, nil
		}
	}
	switch {
	case getUserGroup.GroupName != "" && getUserGroup.GroupID != 0:
		return nil, fmt.Errorf("user group with name '%s' and ID '%d' not found", getUserGroup.GroupName, getUserGroup.GroupID)
	case getUserGroup.GroupName != "":
		return nil, fmt.Errorf("user group with name '%s' not found", getUserGroup.GroupName)
	default:
		return nil, fmt.Errorf("user group with ID '%d' not found", getUserGroup.GroupID)
	}
}

// Update modifies an existing Vault user group via PUT /PasswordVault/API/UserGroups/{groupId}.
//
// The Vault merges the payload into the existing group rather than replacing it: a field that is
// absent keeps its stored value, so the narrow input model cannot disturb the parts of the group
// it does not name.
//
// Every field of the input is sent even when unchanged, so a caller that leaves one empty is
// asking for it to be emptied.
func (s *IdsecPCloudUserGroupsService) Update(updateUserGroup *usergroupsmodels.IdsecPCloudUpdateUserGroup) (*usergroupsmodels.IdsecPCloudUserGroup, error) {
	s.Logger.Info("Updating pCloud user group [%d]", updateUserGroup.GroupID)

	payload, err := serializePayloadWithoutGroupID(updateUserGroup)
	if err != nil {
		return nil, err
	}

	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(userGroupURL, updateUserGroup.GroupID), payload)
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
		return nil, fmt.Errorf("failed to update user group - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.parseUserGroupResponse(response.Body)
}

// Delete removes a Vault user group via DELETE /PasswordVault/API/UserGroups/{groupId}.
func (s *IdsecPCloudUserGroupsService) Delete(deleteUserGroup *usergroupsmodels.IdsecPCloudDeleteUserGroup) error {
	s.Logger.Info("Deleting pCloud user group [%d]", deleteUserGroup.GroupID)

	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(userGroupURL, deleteUserGroup.GroupID), nil, nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete user group - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// serializePayloadWithoutGroupID serializes v to a camelCase JSON map and removes
// "groupId" since it is passed in the URL path, not the request body.
func serializePayloadWithoutGroupID(v interface{}) (map[string]interface{}, error) {
	m, err := common.SerializeJSONCamel(v)
	if err != nil {
		return nil, err
	}
	delete(m, "groupId")
	return m, nil
}

func (s *IdsecPCloudUserGroupsService) parseMemberResponse(responseBody io.ReadCloser, groupID int) (*usergroupsmodels.IdsecPCloudUserGroupMember, error) {
	memberJSON, err := common.DeserializeJSONSnake(responseBody)
	if err != nil {
		return nil, err
	}
	memberJSONMap, ok := memberJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid user group member response format")
	}
	if id, ok := memberJSONMap["id"]; ok {
		memberJSONMap["member_id"] = id
	}
	var member usergroupsmodels.IdsecPCloudUserGroupMember
	if err := mapstructure.Decode(memberJSONMap, &member); err != nil {
		return nil, err
	}
	member.GroupID = groupID
	return &member, nil
}

// AddMember adds a member to a user group via POST /PasswordVault/API/UserGroups/{groupId}/Members.
func (s *IdsecPCloudUserGroupsService) AddMember(req *usergroupsmodels.IdsecPCloudAddUserGroupMember) (*usergroupsmodels.IdsecPCloudUserGroupMember, error) {
	s.Logger.Info("Adding member [%s] of type [%s] to user group [%d]", req.MemberName, req.MemberType, req.GroupID)

	// The wire field is called "memberId" but carries the member's name, so the payload is built
	// by hand: serializing the model would send it as "memberName" and the Vault would reject it.
	// The group ID is not part of the body, it addresses the route.
	payload := map[string]interface{}{
		"memberId":   req.MemberName,
		"memberType": req.MemberType,
	}

	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(userGroupMembersURL, req.GroupID), payload)
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
		return nil, fmt.Errorf("failed to add user group member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	member, err := s.parseMemberResponse(response.Body, req.GroupID)
	if err != nil {
		// Response body may be empty on some PVWA versions — reconstruct from request. The
		// numeric member ID is only ever reported by the Vault, so it stays unset here.
		return &usergroupsmodels.IdsecPCloudUserGroupMember{
			GroupID:    req.GroupID,
			MemberName: req.MemberName,
			MemberType: req.MemberType,
		}, nil
	}
	// The response identifies the member by its numeric ID rather than echoing the name back.
	member.MemberName = req.MemberName
	return member, nil
}

// DeleteMember removes a member from a user group via DELETE /PasswordVault/API/UserGroups/{groupId}/Members/{memberName}.
//
// The member name goes into the path unescaped: the client escapes every path segment before
// sending, so escaping here would double-encode names containing spaces or backslashes.
func (s *IdsecPCloudUserGroupsService) DeleteMember(req *usergroupsmodels.IdsecPCloudDeleteUserGroupMember) error {
	s.Logger.Info("Removing member [%s] from user group [%d]", req.MemberName, req.GroupID)

	memberPath := fmt.Sprintf(userGroupMemberURL, req.GroupID, req.MemberName)
	response, err := s.ISPClient().Delete(context.Background(), memberPath, nil, nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete user group member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ServiceConfig returns the service configuration for IdsecPCloudUserGroupsService.
func (s *IdsecPCloudUserGroupsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
