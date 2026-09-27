// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package localgroups

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
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	commonpcloud "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/common"
	localmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/localgroups/models"
)

const (
	localGroupsURL       = "/PasswordVault/API/UserGroups"
	localGroupURL        = "/PasswordVault/API/UserGroups/%s"
	localGroupMembersURL = "/PasswordVault/API/UserGroups/%s/Members"
	localGroupMemberURL  = "/PasswordVault/API/UserGroups/%s/Members/%s"
)

// groupNotFoundErrorCode is the PVWA error code for a group-not-found 404.
const groupNotFoundErrorCode = "PASWS199E"

// ErrLocalGroupNotFound reports that the requested Vault local group does not exist.
// It wraps common.ErrNotFound so provider Read handlers can call errors.Is(err, common.ErrNotFound)
// to detect any not-found condition and remove the resource from state.
var ErrLocalGroupNotFound = fmt.Errorf("local group not found: %w", common.ErrNotFound)

// ErrLocalGroupMemberNotFound reports that the group does not have the requested member, or that
// the group itself is gone. It wraps common.ErrNotFound so provider Read handlers can call
// errors.Is(err, common.ErrNotFound) to detect the drift and remove the resource from state.
var ErrLocalGroupMemberNotFound = fmt.Errorf("local group member not found: %w", common.ErrNotFound)

// IdsecPCloudLocalGroupsPage is a page of Vault local groups returned by the list operations.
type IdsecPCloudLocalGroupsPage = common.IdsecPage[localmodels.IdsecPCloudLocalGroup]

// IdsecPCloudLocalGroupsService manages Vault local groups and their memberships via the PVWA REST API.
type IdsecPCloudLocalGroupsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecPCloudLocalGroupsService creates a new instance of IdsecPCloudLocalGroupsService.
func NewIdsecPCloudLocalGroupsService(authenticators ...auth.IdsecAuth) (*IdsecPCloudLocalGroupsService, error) {
	svc := &IdsecPCloudLocalGroupsService{}
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

func (s *IdsecPCloudLocalGroupsService) refreshAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// normalizeLocalGroupItemMap renames the API's "id" key to "group_id" to match the GroupID
// mapstructure tag on IdsecPCloudLocalGroup. PVWA sends the id as a JSON number (float64 after
// plain json.Decode), so numeric values are stringified to satisfy the string field type.
func normalizeLocalGroupItemMap(groupMap map[string]interface{}) {
	if id, ok := groupMap["id"]; ok {
		switch v := id.(type) {
		case float64:
			groupMap["group_id"] = fmt.Sprintf("%.0f", v)
		case int64:
			groupMap["group_id"] = fmt.Sprintf("%d", v)
		default:
			groupMap["group_id"] = id
		}
	}
}

func (s *IdsecPCloudLocalGroupsService) parseLocalGroupResponse(responseBody io.ReadCloser) (*localmodels.IdsecPCloudLocalGroup, error) {
	groupJSON, err := common.DeserializeJSONSnake(responseBody)
	if err != nil {
		return nil, err
	}
	groupJSONMap, ok := groupJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid local group response format")
	}
	normalizeLocalGroupItemMap(groupJSONMap)
	var group localmodels.IdsecPCloudLocalGroup
	if err := mapstructure.Decode(groupJSONMap, &group); err != nil {
		return nil, err
	}
	return &group, nil
}

// decodeLocalGroupsFromResultMap decodes one page of the local groups list response, accepting
// either the OData-style "value" key or the legacy "UserGroups" key.
func decodeLocalGroupsFromResultMap(resultMap map[string]interface{}) ([]*localmodels.IdsecPCloudLocalGroup, error) {
	groupsJSON, err := pagination.ExtractItemsFromResult(resultMap, "local groups", "UserGroups")
	if err != nil {
		return nil, err
	}
	for _, group := range groupsJSON {
		if groupMap, ok := group.(map[string]interface{}); ok {
			normalizeLocalGroupItemMap(groupMap)
		}
	}
	var groups []*localmodels.IdsecPCloudLocalGroup
	if err := mapstructure.Decode(groupsJSON, &groups); err != nil {
		return nil, fmt.Errorf("failed to validate local groups: %w", err)
	}
	return groups, nil
}

func (s *IdsecPCloudLocalGroupsService) listLocalGroupsWithFilters(
	ctx context.Context,
	filters *localmodels.IdsecPCloudLocalGroupsFilters,
) (<-chan *IdsecPCloudLocalGroupsPage, error) {
	initialQuery := map[string]string{}
	if filters != nil {
		if filters.Search != "" {
			initialQuery["search"] = filters.Search
		}
		if filters.Sort != "" {
			initialQuery["sort"] = filters.Sort
		}
		if filters.Offset > 0 {
			initialQuery["offset"] = fmt.Sprintf("%d", filters.Offset)
		}
		if filters.Limit > 0 {
			initialQuery["limit"] = fmt.Sprintf("%d", filters.Limit)
		}
		if filters.IncludePredefinedUsers {
			initialQuery["includePredefinedUsers"] = "true"
		}
	}
	return pagination.ListAllPaginated[localmodels.IdsecPCloudLocalGroup](
		ctx,
		pagination.HTTPGetFetch(s.ISPClient(), localGroupsURL, initialQuery),
		pagination.ListPaginatedConfig[localmodels.IdsecPCloudLocalGroup]{
			ResourceName: "local groups",
			Decode:       decodeLocalGroupsFromResultMap,
		},
	)
}

// List returns a channel of IdsecPCloudLocalGroupsPage containing all Vault local groups.
// On failure, returns a non-nil error and a nil channel.
func (s *IdsecPCloudLocalGroupsService) List() (<-chan *IdsecPCloudLocalGroupsPage, error) {
	return s.listLocalGroupsWithFilters(context.Background(), nil)
}

// ListBy returns a channel of IdsecPCloudLocalGroupsPage filtered by the given criteria.
// On failure, returns a non-nil error and a nil channel.
func (s *IdsecPCloudLocalGroupsService) ListBy(filters *localmodels.IdsecPCloudLocalGroupsFilters) (<-chan *IdsecPCloudLocalGroupsPage, error) {
	return s.listLocalGroupsWithFilters(context.Background(), filters)
}

// Create adds a new Vault local group via POST /PasswordVault/API/UserGroups.
func (s *IdsecPCloudLocalGroupsService) Create(addGroup *localmodels.IdsecPCloudAddLocalGroup) (*localmodels.IdsecPCloudLocalGroup, error) {
	s.Logger.Info("Creating pCloud local group [%s]", addGroup.GroupName)

	payload, err := common.SerializeJSONCamel(addGroup)
	if err != nil {
		return nil, err
	}

	response, err := s.ISPClient().Post(context.Background(), localGroupsURL, payload)
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
		return nil, fmt.Errorf("failed to create local group - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	group, err := s.parseLocalGroupResponse(response.Body)
	if err != nil {
		return nil, err
	}
	if group.GroupID == "" {
		s.Logger.Warning("Created local group [%s] came back without an ID in the 201 response — resolving by name", addGroup.GroupName)
		return s.Get(&localmodels.IdsecPCloudGetLocalGroup{GroupName: addGroup.GroupName})
	}
	return group, nil
}

// Get retrieves a single Vault local group by ID, name, or both.
//
// The group is resolved through the list endpoint. The name, when given, narrows the server-side
// search; the ID, when set, selects the exact match. Names are matched case-insensitively.
func (s *IdsecPCloudLocalGroupsService) Get(getGroup *localmodels.IdsecPCloudGetLocalGroup) (*localmodels.IdsecPCloudLocalGroup, error) {
	s.Logger.Info("Retrieving pCloud local group [%s] - [%s]", getGroup.GroupID, getGroup.GroupName)
	if getGroup.GroupID == "" && getGroup.GroupName == "" {
		return nil, fmt.Errorf("either local group ID or local group name must be provided")
	}

	pages, err := s.listLocalGroupsWithFilters(context.Background(), &localmodels.IdsecPCloudLocalGroupsFilters{
		Search:                 getGroup.GroupName,
		IncludePredefinedUsers: true,
	})
	if err != nil {
		return nil, err
	}
	for page := range pages {
		for _, group := range page.Items {
			if getGroup.GroupID != "" && group.GroupID != getGroup.GroupID {
				continue
			}
			if getGroup.GroupName != "" && !strings.EqualFold(group.GroupName, getGroup.GroupName) {
				continue
			}
			return group, nil
		}
	}
	switch {
	case getGroup.GroupName != "" && getGroup.GroupID != "":
		return nil, fmt.Errorf("local group with name '%s' and ID '%s' not found: %w", getGroup.GroupName, getGroup.GroupID, ErrLocalGroupNotFound)
	case getGroup.GroupName != "":
		return nil, fmt.Errorf("local group with name '%s' not found: %w", getGroup.GroupName, ErrLocalGroupNotFound)
	default:
		return nil, fmt.Errorf("local group with ID '%s' not found: %w", getGroup.GroupID, ErrLocalGroupNotFound)
	}
}

// Update modifies an existing Vault local group via PUT /PasswordVault/API/UserGroups/{groupId}.
func (s *IdsecPCloudLocalGroupsService) Update(updateGroup *localmodels.IdsecPCloudUpdateLocalGroup) (*localmodels.IdsecPCloudLocalGroup, error) {
	s.Logger.Info("Updating pCloud local group [%s]", updateGroup.GroupID)
	if updateGroup.GroupID == "" {
		return nil, fmt.Errorf("local group ID must be provided")
	}

	payload, err := common.SerializeJSONCamel(updateGroup)
	if err != nil {
		return nil, err
	}
	delete(payload, "groupId")
	// PVWA requires groupName in the PUT body (BaseUserGroup has [CybRequired] on it).
	// If the caller did not supply a new name, keep the existing name by fetching it first.
	if _, hasName := payload["groupName"]; !hasName {
		existing, err := s.Get(&localmodels.IdsecPCloudGetLocalGroup{GroupID: updateGroup.GroupID})
		if err != nil {
			return nil, fmt.Errorf("failed to resolve group name for update: %w", err)
		}
		payload["groupName"] = existing.GroupName
	}

	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(localGroupURL, updateGroup.GroupID), payload)
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
		return nil, fmt.Errorf("failed to update local group - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.parseLocalGroupResponse(response.Body)
}

// Delete removes a Vault local group via DELETE /PasswordVault/API/UserGroups/{groupId}.
func (s *IdsecPCloudLocalGroupsService) Delete(deleteGroup *localmodels.IdsecPCloudDeleteLocalGroup) error {
	s.Logger.Info("Deleting pCloud local group [%s]", deleteGroup.GroupID)
	if deleteGroup.GroupID == "" {
		return fmt.Errorf("local group ID must be provided")
	}

	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(localGroupURL, deleteGroup.GroupID), nil, nil)
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
		return fmt.Errorf("failed to delete local group - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// AddMember adds a member to a local group via POST /PasswordVault/API/UserGroups/{groupId}/Members.
//
// The PVWA wire field is "memberId" (not "memberName"); it carries the user or group name to add.
// If the response body cannot be decoded the member is returned with the fields from the request,
// since the 201 status already confirmed the add succeeded.
func (s *IdsecPCloudLocalGroupsService) AddMember(req *localmodels.IdsecPCloudAddLocalGroupMember) (*localmodels.IdsecPCloudLocalGroupMember, error) {
	s.Logger.Info("Adding member [%s] to local group [%s]", req.MemberName, req.GroupID)
	if req.GroupID == "" {
		return nil, fmt.Errorf("local group ID must be provided")
	}

	memberType := req.MemberType
	if memberType == "" {
		memberType = "Vault"
	}
	payload := map[string]interface{}{
		"memberId":   req.MemberName,
		"memberType": memberType,
	}

	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(localGroupMembersURL, req.GroupID), payload)
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
		return nil, fmt.Errorf("failed to add local group member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	fallback := &localmodels.IdsecPCloudLocalGroupMember{
		GroupID:    req.GroupID,
		MemberName: req.MemberName,
		MemberType: memberType,
	}
	memberJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		s.Logger.Warning("AddMember: could not decode 201 response body for group [%s] member [%s]: %v — returning request fields", req.GroupID, req.MemberName, err)
		return fallback, nil
	}
	memberMap, ok := memberJSON.(map[string]interface{})
	if !ok {
		s.Logger.Warning("AddMember: unexpected response type %T for group [%s] member [%s] — returning request fields", memberJSON, req.GroupID, req.MemberName)
		return fallback, nil
	}
	s.normalizeLocalGroupMemberItemMap(memberMap)
	var member localmodels.IdsecPCloudLocalGroupMember
	if err := mapstructure.Decode(memberMap, &member); err != nil {
		s.Logger.Warning("AddMember: could not decode member map for group [%s] member [%s]: %v — returning request fields", req.GroupID, req.MemberName, err)
		return fallback, nil
	}
	member.GroupID = req.GroupID
	member.MemberName = req.MemberName
	return &member, nil
}

// normalizeLocalGroupMemberItemMap maps the keys a member item can arrive under onto the fields of
// IdsecPCloudLocalGroupMember.
//
// PVWA returns member "id" as a JSON number (e.g. 2), but MembershipID is a string.
// Numeric IDs are stringified here before mapstructure decodes the map.
func (s *IdsecPCloudLocalGroupsService) normalizeLocalGroupMemberItemMap(memberMap map[string]interface{}) {
	if id, ok := memberMap["id"]; ok {
		switch v := id.(type) {
		case float64:
			memberMap["membership_id"] = fmt.Sprintf("%.0f", v)
		case int64:
			memberMap["membership_id"] = fmt.Sprintf("%d", v)
		default:
			memberMap["membership_id"] = id
		}
	}
	if _, ok := memberMap["member_name"]; !ok {
		for _, key := range []string{"member_name", "user_name", "username", "memberName", "name"} {
			if name, ok := memberMap[key]; ok {
				memberMap["member_name"] = name
				break
			}
		}
	}
	if _, ok := memberMap["member_type"]; !ok {
		for _, key := range []string{"member_type", "memberType", "type"} {
			if mt, ok := memberMap[key]; ok {
				memberMap["member_type"] = mt
				break
			}
		}
	}
}

// pvwaErrorCode reports the PVWA error code from a failed response body, or "" if not a PVWA error.
func pvwaErrorCode(body []byte) string {
	var pvwaError struct {
		ErrorCode string `json:"ErrorCode"` //nolint:tagliatelle
	}
	if err := json.Unmarshal(body, &pvwaError); err != nil {
		return ""
	}
	return pvwaError.ErrorCode
}

// listGroupMembers reads the members of a local group from GET /PasswordVault/API/UserGroups/{groupId}.
//
// PVWA embeds the members array in the group's own representation; there is no GET on the
// /Members sub-resource. The group's "members" key carries the array (omitted when the group has
// no members rather than sent empty).
//
// A 404 carrying PVWA's group-not-found code (PASWS199E) wraps ErrLocalGroupMemberNotFound; any
// other error stays a plain read error so a caller refreshing state cannot drop a live membership
// by mistaking a network problem for an absent record.
func (s *IdsecPCloudLocalGroupsService) listGroupMembers(groupID string) ([]*localmodels.IdsecPCloudLocalGroupMember, error) {
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(localGroupURL, groupID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read group response for local group %s: %w", groupID, err)
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusNotFound && pvwaErrorCode(body) == groupNotFoundErrorCode {
			return nil, fmt.Errorf("local group '%s' does not exist: %w", groupID, ErrLocalGroupMemberNotFound)
		}
		return nil, fmt.Errorf("failed to read members of local group %s - [%d] - [%s]", groupID, response.StatusCode, body)
	}

	payload, err := common.DeserializeJSONSnake(io.NopCloser(strings.NewReader(string(body))))
	if err != nil {
		return nil, err
	}
	payloadMap, ok := payload.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected local group response type %T", payload)
	}

	// Members are under the "members" key and omitted entirely when the group is empty.
	raw, exists := payloadMap["members"]
	if !exists {
		return nil, nil
	}
	memberItems, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected members field type %T in local group response", raw)
	}

	for _, item := range memberItems {
		if m, ok := item.(map[string]interface{}); ok {
			s.normalizeLocalGroupMemberItemMap(m)
		}
	}

	var members []*localmodels.IdsecPCloudLocalGroupMember
	if err := mapstructure.Decode(memberItems, &members); err != nil {
		return nil, fmt.Errorf("failed to decode local group members: %w", err)
	}
	for _, member := range members {
		member.GroupID = groupID
	}
	return members, nil
}

// GetMember retrieves a single membership of a Vault local group.
//
// PVWA has no GET-by-name for a member, so the members list for the group is fetched and matched
// case-insensitively. Both an absent member and a missing group wrap ErrLocalGroupMemberNotFound.
//
// Note: PVWA's member wire shape carries only "username" and "id" — MemberType is never returned
// in read responses. The returned IdsecPCloudLocalGroupMember always has MemberType == "".
// Callers must preserve MemberType from config/state and never overwrite it from this result.
func (s *IdsecPCloudLocalGroupsService) GetMember(req *localmodels.IdsecPCloudGetLocalGroupMember) (*localmodels.IdsecPCloudLocalGroupMember, error) {
	s.Logger.Info("Retrieving member [%s] of pCloud local group [%s]", req.MemberName, req.GroupID)
	if req.GroupID == "" || req.MemberName == "" {
		return nil, fmt.Errorf("both local group ID and member name must be provided")
	}

	members, err := s.listGroupMembers(req.GroupID)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		if strings.EqualFold(member.MemberName, req.MemberName) {
			return member, nil
		}
	}
	return nil, fmt.Errorf("member '%s' of local group '%s': %w", req.MemberName, req.GroupID, ErrLocalGroupMemberNotFound)
}

// DeleteMember removes a member from a local group via DELETE /PasswordVault/API/UserGroups/{groupId}/Members/{memberName}.
//
// The member name goes into the path unescaped: the client escapes every path segment before
// sending, so escaping here would double-encode names containing spaces or backslashes.
func (s *IdsecPCloudLocalGroupsService) DeleteMember(req *localmodels.IdsecPCloudDeleteLocalGroupMember) error {
	s.Logger.Info("Removing member [%s] from local group [%s]", req.MemberName, req.GroupID)
	if req.GroupID == "" {
		return fmt.Errorf("local group ID must be provided")
	}

	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(localGroupMemberURL, req.GroupID, req.MemberName), nil, nil)
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
		return fmt.Errorf("failed to delete local group member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ServiceConfig returns the service configuration for IdsecPCloudLocalGroupsService.
func (s *IdsecPCloudLocalGroupsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
