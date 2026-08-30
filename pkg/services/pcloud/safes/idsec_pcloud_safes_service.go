package safes

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
	commonpcloud "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/common"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"

	"io"
	"net/http"
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

	RolesService *roles.IdsecIdentityRolesService
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
	pcloudSafesService.RolesService, err = roles.NewIdsecIdentityRolesService(ispAuth)
	if err != nil {
		return nil, err
	}
	return pcloudSafesService, nil
}

func (s *IdsecPCloudSafesService) refreshPCloudSafesAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func normalizeSafeItemMap(safeMap map[string]interface{}) {
	if sid, ok := safeMap["safe_url_id"]; ok {
		safeMap["safe_id"] = sid
	}
}

func decodeSafesFromListJSON(safesJSON []interface{}) ([]*safesmodels.IdsecPCloudSafe, error) {
	for i, safe := range safesJSON {
		if safeMap, ok := safe.(map[string]interface{}); ok {
			normalizeSafeItemMap(safeMap)
			safesJSON[i] = safeMap
		}
	}
	var safes []*safesmodels.IdsecPCloudSafe
	if err := mapstructure.Decode(safesJSON, &safes); err != nil {
		return nil, err
	}
	return safes, nil
}

// isIdentityRole reports whether the given member name resolves to a role in the identity
// service. pCloud's backend reports identity roles under the generic "Group" member type,
// so we use the identity directory query to distinguish true groups from roles.
// Errors are intentionally swallowed and treated as a negative result: the type override
// is best-effort enrichment and must never fail the surrounding safe-member call.
func (s *IdsecPCloudSafesService) isIdentityRole(memberName string) bool {
	if memberName == "" || s.RolesService == nil {
		return false
	}
	role, err := s.RolesService.Get(&rolesmodels.IdsecIdentityGetRole{RoleName: memberName})
	if err != nil {
		return false
	}
	return role != nil && role.RoleID != ""
}

// enrichMembersWithRoleType walks the given members and, in parallel, promotes the member
// type of any pCloud-reported "Group" that is actually an identity role to "Role".
func (s *IdsecPCloudSafesService) enrichMembersWithRoleType(members []*safesmodels.IdsecPCloudSafeMember) {
	var wg sync.WaitGroup
	for _, member := range members {
		if member == nil || member.MemberType != safesmodels.Group {
			continue
		}
		wg.Add(1)
		go func(m *safesmodels.IdsecPCloudSafeMember) {
			defer wg.Done()
			if s.isIdentityRole(m.MemberName) {
				m.MemberType = safesmodels.Role
			}
		}(member)
	}
	wg.Wait()
}

// decodeSafesFromResultMap decodes one page of the safes list response, accepting either the
// OData-style "value" key or the legacy "Safes" key.
func decodeSafesFromResultMap(resultMap map[string]interface{}) ([]*safesmodels.IdsecPCloudSafe, error) {
	safesJSON, err := pagination.ExtractItemsFromResult(resultMap, "safes", "Safes")
	if err != nil {
		return nil, err
	}
	return decodeSafesFromListJSON(safesJSON)
}

func (s *IdsecPCloudSafesService) listSafesWithFilters(
	ctx context.Context,
	search string,
	sort string,
	offset int,
	limit int,
) (<-chan *IdsecPCloudSafesPage, error) {
	initialQuery := map[string]string{}
	if search != "" {
		initialQuery["search"] = search
	}
	if sort != "" {
		initialQuery["sort"] = sort
	}
	if offset > 0 {
		initialQuery["offset"] = fmt.Sprintf("%d", offset)
	}
	if limit > 0 {
		initialQuery["limit"] = fmt.Sprintf("%d", limit)
	}
	return pagination.ListAllPaginated[safesmodels.IdsecPCloudSafe](
		ctx,
		pagination.HTTPGetFetch(s.ISPClient(), safesURL, initialQuery),
		pagination.ListPaginatedConfig[safesmodels.IdsecPCloudSafe]{
			ResourceName: "safes",
			Decode:       decodeSafesFromResultMap,
		},
	)
}

// decodeSafeMembersFromResultMap decodes one page of the safe-members list response and applies
// the permission-set classification to each member.
func decodeSafeMembersFromResultMap(resultMap map[string]interface{}) ([]*safesmodels.IdsecPCloudSafeMember, error) {
	membersJSON, err := pagination.ExtractItemsFromResult(resultMap, "safe members")
	if err != nil {
		return nil, err
	}
	for i, safeMember := range membersJSON {
		if safeMemberMap, ok := safeMember.(map[string]interface{}); ok {
			if sid, ok := safeMemberMap["safe_url_id"]; ok {
				membersJSON[i].(map[string]interface{})["safe_id"] = sid
			}
		}
	}
	var members []*safesmodels.IdsecPCloudSafeMember
	if err := mapstructure.Decode(membersJSON, &members); err != nil {
		return nil, fmt.Errorf("failed to validate safe members: %w", err)
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
	return members, nil
}

func (s *IdsecPCloudSafesService) listSafeMembersWithFilters(
	ctx context.Context,
	safeID string,
	search string,
	sort string,
	offset int,
	limit int,
	memberType string,
) (<-chan *IdsecPCloudSafeMembersPage, error) {
	initialQuery := map[string]string{}
	if search != "" {
		initialQuery["search"] = search
	}
	if sort != "" {
		initialQuery["sort"] = sort
	}
	if offset > 0 {
		initialQuery["offset"] = fmt.Sprintf("%d", offset)
	}
	if limit > 0 {
		initialQuery["limit"] = fmt.Sprintf("%d", limit)
	}
	if memberType != "" {
		initialQuery["filter"] = fmt.Sprintf("memberType eq %s", memberType)
	}
	return pagination.ListAllPaginated[safesmodels.IdsecPCloudSafeMember](
		ctx,
		pagination.HTTPGetFetch(s.ISPClient(), fmt.Sprintf(safeMembersURL, safeID), initialQuery),
		pagination.ListPaginatedConfig[safesmodels.IdsecPCloudSafeMember]{
			ResourceName: "safe members",
			Decode: func(resultMap map[string]interface{}) ([]*safesmodels.IdsecPCloudSafeMember, error) {
				members, err := decodeSafeMembersFromResultMap(resultMap)
				if err != nil {
					return nil, err
				}
				s.enrichMembersWithRoleType(members)
				return members, nil
			},
		},
	)
}

func (s *IdsecPCloudSafesService) parseSafeResponse(responseBody io.ReadCloser) (*safesmodels.IdsecPCloudSafe, error) {
	safeJSON, err := common.DeserializeJSONSnake(responseBody)
	if err != nil {
		return nil, err
	}
	safeJSONMap, ok := safeJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid safe response format")
	}
	normalizeSafeItemMap(safeJSONMap)
	var safe safesmodels.IdsecPCloudSafe
	if err := mapstructure.Decode(safeJSONMap, &safe); err != nil {
		return nil, err
	}
	return &safe, nil
}

// List returns a channel of IdsecPCloudSafesPage containing all safes.
// On failure, returns a non-nil error and a nil channel. On success, returns a channel that yields the pages.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm?
func (s *IdsecPCloudSafesService) List() (<-chan *IdsecPCloudSafesPage, error) {
	return s.ListContext(context.Background())
}

// ListContext is like List but accepts a context.Context. Callers that stop iterating the
// returned channel early must cancel the context to release the producer goroutine and any
// in-flight request.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm?
func (s *IdsecPCloudSafesService) ListContext(ctx context.Context) (<-chan *IdsecPCloudSafesPage, error) {
	return s.listSafesWithFilters(
		ctx,
		"",
		"",
		0,
		0,
	)
}

// ListBy returns a channel of IdsecPCloudSafesPage containing safes filtered by the given filters.
// On failure, returns a non-nil error and a nil channel. On success, returns a channel that yields the pages.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm?
func (s *IdsecPCloudSafesService) ListBy(safesFilters *safesmodels.IdsecPCloudSafesFilters) (<-chan *IdsecPCloudSafesPage, error) {
	return s.ListByContext(context.Background(), safesFilters)
}

// ListByContext is like ListBy but accepts a context.Context. Callers that stop iterating the
// returned channel early must cancel the context to release the producer goroutine and any
// in-flight request.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm?
func (s *IdsecPCloudSafesService) ListByContext(ctx context.Context, safesFilters *safesmodels.IdsecPCloudSafesFilters) (<-chan *IdsecPCloudSafesPage, error) {
	return s.listSafesWithFilters(
		ctx,
		safesFilters.Search,
		safesFilters.Sort,
		safesFilters.Offset,
		safesFilters.Limit,
	)
}

// ListMembers returns a channel of IdsecPCloudSafeMembersPage containing all safe members.
// On failure, returns a non-nil error and a nil channel. On success, returns a channel that yields the pages.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Members.htm
func (s *IdsecPCloudSafesService) ListMembers(listSafeMembers *safesmodels.IdsecPCloudListSafeMembers) (<-chan *IdsecPCloudSafeMembersPage, error) {
	return s.ListMembersContext(context.Background(), listSafeMembers)
}

// ListMembersContext is like ListMembers but accepts a context.Context. Callers that stop iterating
// the returned channel early must cancel the context to release the producer goroutine and any
// in-flight request.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Members.htm
func (s *IdsecPCloudSafesService) ListMembersContext(ctx context.Context, listSafeMembers *safesmodels.IdsecPCloudListSafeMembers) (<-chan *IdsecPCloudSafeMembersPage, error) {
	return s.listSafeMembersWithFilters(
		ctx,
		listSafeMembers.SafeID,
		"",
		"",
		0,
		0,
		"",
	)
}

// ListMembersBy returns a channel of IdsecPCloudSafeMembersPage containing safe members filtered by the given filters.
// On failure, returns a non-nil error and a nil channel. On success, returns a channel that yields the pages.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Members.htm
func (s *IdsecPCloudSafesService) ListMembersBy(safeMembersFilters *safesmodels.IdsecPCloudSafeMembersFilters) (<-chan *IdsecPCloudSafeMembersPage, error) {
	return s.ListMembersByContext(context.Background(), safeMembersFilters)
}

// ListMembersByContext is like ListMembersBy but accepts a context.Context. Callers that stop
// iterating the returned channel early must cancel the context to release the producer goroutine
// and any in-flight request.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Members.htm
func (s *IdsecPCloudSafesService) ListMembersByContext(ctx context.Context, safeMembersFilters *safesmodels.IdsecPCloudSafeMembersFilters) (<-chan *IdsecPCloudSafeMembersPage, error) {
	return s.listSafeMembersWithFilters(
		ctx,
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
	return s.parseSafeResponse(response.Body)
}

// GetMember retrieves a safe member by its safe ID and member name.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Member.htm
func (s *IdsecPCloudSafesService) GetMember(getSafeMember *safesmodels.IdsecPCloudGetSafeMember) (*safesmodels.IdsecPCloudSafeMember, error) {
	s.Logger.Info("Retrieving safe member [%s] [%s]", getSafeMember.SafeID, getSafeMember.MemberName)

	// Resolve whether the requested name is an identity role concurrently with the pCloud
	// fetch so the override does not add a serial round-trip on the happy path.
	isRoleChan := make(chan bool, 1)
	go func() {
		isRoleChan <- s.isIdentityRole(getSafeMember.MemberName)
	}()

	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(safeMemberURL, getSafeMember.SafeID, getSafeMember.MemberName), nil)
	if err != nil {
		<-isRoleChan
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		<-isRoleChan
		return nil, fmt.Errorf("failed to retrieve safe member - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	safeMemberJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		<-isRoleChan
		return nil, err
	}
	safeMemberJSONMap, ok := safeMemberJSON.(map[string]interface{})
	if !ok {
		<-isRoleChan
		return nil, fmt.Errorf("invalid safe member response format")
	}
	if safeID, ok := safeMemberJSONMap["safe_url_id"]; ok {
		safeMemberJSONMap["safe_id"] = safeID
	}
	var safeMember safesmodels.IdsecPCloudSafeMember
	err = mapstructure.Decode(safeMemberJSON, &safeMember)
	if err != nil {
		<-isRoleChan
		return nil, err
	}
	safeMember.PermissionSet = safesmodels.Custom
	for permissionSet, permissions := range SafeMembersPermissionsSets {
		if reflect.DeepEqual(safeMember.Permissions, permissions) {
			safeMember.PermissionSet = permissionSet
			break
		}
	}
	if isRole := <-isRoleChan; isRole && safeMember.MemberType == safesmodels.Group {
		safeMember.MemberType = safesmodels.Role
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
	response, existingSafe, err := commonpcloud.CreateWithGatewayTimeoutRecovery(
		func() (*http.Response, error) {
			return s.ISPClient().Post(context.Background(), safesURL, addSafeJSON)
		},
		func() (*safesmodels.IdsecPCloudSafe, error) {
			return s.Get(&safesmodels.IdsecPCloudGetSafe{SafeName: addSafe.SafeName})
		},
	)
	if err != nil {
		return nil, err
	}
	if existingSafe != nil {
		s.Logger.Info("Safe [%s] recovered after gateway timeout", addSafe.SafeName)
		return existingSafe, nil
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
	return s.parseSafeResponse(response.Body)
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
	safeMemberJSONMap, ok := safeMemberJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid safe member response format")
	}
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
	return s.parseSafeResponse(response.Body)
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
	safeMemberJSONMap, ok := safeMemberJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid safe member response format")
	}
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
