package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles"
	authprofilesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles/models"
	policymodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/policies/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
)

const (
	savePolicyURL        = "Policy/SavePolicyBlock3"
	deletePolicyURL      = "Policy/DeletePolicyBlock"
	listPoliciesLinksURL = "Policy/GetNicePlinks"
	getPolicyURL         = "Policy/GetPolicyBlock"
)

var defaultPolicySettings = map[string]interface{}{
	"AuthenticationEnabled":                                "true",
	"/Core/Authentication/CookieAllowPersist":              "false",
	"/Core/Authentication/AuthSessionMaxConcurrent":        0,
	"/Core/Authentication/AllowIwa":                        "true",
	"/Core/Authentication/IwaSetKnownEndpoint":             "false",
	"/Core/Authentication/IwaSatisfiesAllMechs":            "false",
	"/Core/Authentication/AllowZso":                        "true",
	"/Core/Authentication/ZsoSkipChallenge":                "true",
	"/Core/Authentication/ZsoSetKnownEndpoint":             "false",
	"/Core/Authentication/ZsoSatisfiesAllMechs":            "false",
	"/Core/Authentication/NoMfaMechLogin":                  "false",
	"/Core/Authentication/FederatedLoginAllowsMfa":         "false",
	"/Core/Authentication/FederatedLoginSatisfiesAllMechs": "false",
	"/Core/MfaRestrictions/BlockMobileMechsOnMobileLogin":  "false",
	"/Core/Authentication/ContinueFailedSessions":          "true",
	"/Core/Authentication/SkipMechsInFalseAdvance":         "true",
	"/Core/Authentication/AllowLoginMfaCache":              "false",
}

// IdsecIdentityPoliciesService is the service for managing identity policies.
type IdsecIdentityPoliciesService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth            *auth.IdsecISPAuth
	client             *isp.IdsecISPServiceClient
	RolesService       *roles.IdsecIdentityRolesService
	AuthProfileService *authprofiles.IdsecIdentityAuthProfilesService

	DoPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
}

// NewIdsecIdentityPoliciesService creates a new instance of IdsecIdentityPoliciesService.
func NewIdsecIdentityPoliciesService(authenticators ...auth.IdsecAuth) (*IdsecIdentityPoliciesService, error) {
	identityPoliciesService := &IdsecIdentityPoliciesService{}
	var identityPoliciesServiceInterface services.IdsecService = identityPoliciesService
	baseService, err := services.NewIdsecBaseService(identityPoliciesServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "", "", "api/idadmin", identityPoliciesService.refreshIdentityPoliciesAuth)
	if err != nil {
		return nil, err
	}
	client.UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})
	identityPoliciesService.client = client
	identityPoliciesService.ispAuth = ispAuth
	identityPoliciesService.IdsecBaseService = baseService
	identityPoliciesService.RolesService, err = roles.NewIdsecIdentityRolesService(ispAuth)
	if err != nil {
		return nil, err
	}
	identityPoliciesService.AuthProfileService, err = authprofiles.NewIdsecIdentityAuthProfilesService(ispAuth)
	if err != nil {
		return nil, err
	}
	return identityPoliciesService, nil
}

func (s *IdsecIdentityPoliciesService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoPost != nil {
		return s.DoPost
	}
	return s.client.Post
}

func (s *IdsecIdentityPoliciesService) refreshIdentityPoliciesAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecIdentityPoliciesService) listPolicyLinks() ([]map[string]interface{}, error) {
	s.Logger.Debug("Listing identity policy links")
	response, err := s.postOperation()(context.Background(), listPoliciesLinksURL, map[string]interface{}{})
	if err != nil {
		s.Logger.Error("Error listing identity policy links: %s", err.Error())
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list identity policy links - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to list identity policy links - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve identity policy links - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{})["Results"].([]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve identity policy links - [%v]", result)
	}
	policyLinksData := result["Result"].(map[string]interface{})["Results"].([]interface{})
	var policyLinks []map[string]interface{}
	for _, policyLinkData := range policyLinksData {
		policyLinkMap, ok := policyLinkData.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse identity policy link data - [%v]", policyLinkData)
		}
		policyLinkMapRow, ok := policyLinkMap["Row"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse identity policy link row data - [%v]", policyLinkMap)
		}
		policyLinks = append(policyLinks, policyLinkMapRow)
	}
	return policyLinks, nil
}

// CreatePolicy creates a new identity policy.
func (s *IdsecIdentityPoliciesService) CreatePolicy(createPolicy *policymodels.IdsecIdentityCreatePolicy) (*policymodels.IdsecIdentityPolicy, error) {
	s.Logger.Debug("Creating a new identity policy")
	if createPolicy.AuthProfileName == "" {
		return nil, fmt.Errorf("auth profile name must be supplied")
	}
	isActive := true
	if createPolicy.PolicyStatus != "" {
		isActive = createPolicy.PolicyStatus == policymodels.PolicyStatusActive
	}

	// Channels to collect results from parallel operations
	type policyLinksResult struct {
		links []map[string]interface{}
		err   error
	}
	type authProfileResult struct {
		profile *authprofilesmodels.IdsecIdentityAuthProfile
		err     error
	}
	type roleIDsResult struct {
		ids []string
		err error
	}

	policyLinksChan := make(chan policyLinksResult, 1)
	authProfileChan := make(chan authProfileResult, 1)
	roleIDsChan := make(chan roleIDsResult, 1)

	// Resolve policy links in parallel
	go func() {
		links, err := s.listPolicyLinks()
		policyLinksChan <- policyLinksResult{links: links, err: err}
	}()

	// Resolve auth profile in parallel
	go func() {
		if createPolicy.AuthProfileName != "" {
			profile, err := s.AuthProfileService.AuthProfile(&authprofilesmodels.IdsecIdentityGetAuthProfile{
				AuthProfileName: createPolicy.AuthProfileName,
			})
			authProfileChan <- authProfileResult{profile: profile, err: err}
		} else {
			authProfileChan <- authProfileResult{profile: nil, err: nil}
		}
	}()

	// Resolve role ids in parallel
	go func() {
		roleIDs := []string{}
		var resErr error
		for _, roleName := range createPolicy.RoleNames {
			role, err := s.RolesService.Role(&rolesmodels.IdsecIdentityGetRole{
				RoleName: roleName,
			})
			if err != nil {
				resErr = err
				break
			}
			roleIDs = append(roleIDs, role.RoleID)
		}
		roleIDsChan <- roleIDsResult{ids: roleIDs, err: resErr}
	}()

	// Collect results
	policyLinksRes := <-policyLinksChan
	authProfileRes := <-authProfileChan
	roleIDsRes := <-roleIDsChan

	// Check for errors
	if policyLinksRes.err != nil {
		return nil, policyLinksRes.err
	}
	if authProfileRes.err != nil {
		return nil, authProfileRes.err
	}
	if roleIDsRes.err != nil {
		return nil, roleIDsRes.err
	}

	policyLinks := policyLinksRes.links
	authProfile := authProfileRes.profile
	roleIDs := roleIDsRes.ids

	// Prepare policy links
	policyName := fmt.Sprintf("/Policy/%s", createPolicy.PolicyName)
	newPolicyLink := map[string]interface{}{
		"Description":     createPolicy.Description,
		"PolicySet":       policyName,
		"Priority":        1,
		"Filters":         []interface{}{},
		"Allowedpolicies": []interface{}{},
	}
	if !isActive {
		newPolicyLink["LinkType"] = "Inactive"
	} else {
		if len(roleIDs) > 0 {
			newPolicyLink["LinkType"] = "Role"
			newPolicyLink["Params"] = roleIDs
		} else {
			newPolicyLink["LinkType"] = "Global"
		}
	}
	policyLinks = append([]map[string]interface{}{newPolicyLink}, policyLinks...)
	policySettings := map[string]interface{}{}
	if !createPolicy.DoNotUseDefaults {
		policySettings = maps.Clone(defaultPolicySettings)
	}
	if authProfile != nil {
		policySettings["/Core/Authentication/AuthenticationRulesDefaultProfileId"] = authProfile.AuthProfileID
	}
	for key, value := range createPolicy.Settings {
		policySettings[key] = value
	}
	policyBlock := map[string]interface{}{
		"plinks": policyLinks,
		"policy": map[string]interface{}{
			"Path":        policyName,
			"Version":     1,
			"Description": createPolicy.Description,
			"Settings":    policySettings,
			"Newpolicy":   "true",
		},
	}
	response, err := s.postOperation()(context.Background(), savePolicyURL, policyBlock)
	if err != nil {
		s.Logger.Error("Error creating identity policy: %s", err.Error())
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create identity policy - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to create identity policy - [%v]", result)
	}
	return s.Policy(&policymodels.IdsecIdentityGetPolicy{
		PolicyName: createPolicy.PolicyName,
	})
}

// UpdatePolicy updates an existing identity policy.
func (s *IdsecIdentityPoliciesService) UpdatePolicy(updatePolicy *policymodels.IdsecIdentityUpdatePolicy) (*policymodels.IdsecIdentityPolicy, error) {
	s.Logger.Debug("Updating identity policy")

	isActive := true
	if updatePolicy.PolicyStatus != "" {
		isActive = updatePolicy.PolicyStatus == policymodels.PolicyStatusActive
	}

	// Channels for parallel operations
	type existingPolicyResult struct {
		policy *policymodels.IdsecIdentityPolicy
		err    error
	}
	type authProfileResult struct {
		profile *authprofilesmodels.IdsecIdentityAuthProfile
		err     error
	}
	type policyLinksResult struct {
		links []map[string]interface{}
		err   error
	}
	type roleIDsResult struct {
		ids []string
		err error
	}

	existingPolicyChan := make(chan existingPolicyResult, 1)
	authProfileChan := make(chan authProfileResult, 1)
	policyLinksChan := make(chan policyLinksResult, 1)
	roleIDsChan := make(chan roleIDsResult, 1)

	// Fetch existing policy in parallel
	go func() {
		policy, err := s.Policy(&policymodels.IdsecIdentityGetPolicy{
			PolicyName: updatePolicy.PolicyName,
		})
		existingPolicyChan <- existingPolicyResult{policy: policy, err: err}
	}()

	// Fetch policy links in parallel
	go func() {
		links, err := s.listPolicyLinks()
		policyLinksChan <- policyLinksResult{links: links, err: err}
	}()

	// Resolve auth profile if provided
	go func() {
		if updatePolicy.AuthProfileName != "" {
			profile, err := s.AuthProfileService.AuthProfile(&authprofilesmodels.IdsecIdentityGetAuthProfile{
				AuthProfileName: updatePolicy.AuthProfileName,
			})
			authProfileChan <- authProfileResult{profile: profile, err: err}
		} else {
			authProfileChan <- authProfileResult{profile: nil, err: nil}
		}
	}()

	// Resolve role IDs in parallel if RoleNames is provided
	go func() {
		if updatePolicy.RoleNames != nil {
			roleIDs := make([]string, len(updatePolicy.RoleNames))
			errChan := make(chan error, len(updatePolicy.RoleNames))
			idChan := make(chan struct {
				index int
				id    string
			}, len(updatePolicy.RoleNames))

			for i, roleName := range updatePolicy.RoleNames {
				go func(index int, name string) {
					role, err := s.RolesService.Role(&rolesmodels.IdsecIdentityGetRole{
						RoleName: name,
					})
					if err != nil {
						errChan <- err
						return
					}
					idChan <- struct {
						index int
						id    string
					}{index: index, id: role.RoleID}
				}(i, roleName)
			}

			// Collect results
			for i := 0; i < len(updatePolicy.RoleNames); i++ {
				select {
				case err := <-errChan:
					roleIDsChan <- roleIDsResult{err: err}
					return
				case result := <-idChan:
					roleIDs[result.index] = result.id
				}
			}

			roleIDsChan <- roleIDsResult{ids: roleIDs, err: nil}
		} else {
			roleIDsChan <- roleIDsResult{ids: nil, err: nil}
		}
	}()

	// Collect results
	existingPolicyRes := <-existingPolicyChan
	policyLinksRes := <-policyLinksChan
	authProfileRes := <-authProfileChan
	roleIDsRes := <-roleIDsChan

	// Check for errors
	if existingPolicyRes.err != nil {
		return nil, existingPolicyRes.err
	}
	if policyLinksRes.err != nil {
		return nil, policyLinksRes.err
	}
	if authProfileRes.err != nil {
		return nil, authProfileRes.err
	}
	if roleIDsRes.err != nil {
		return nil, roleIDsRes.err
	}

	existingPolicy := existingPolicyRes.policy
	policyLinks := policyLinksRes.links

	// Update policy fields
	if updatePolicy.Description != "" {
		existingPolicy.Description = updatePolicy.Description
	}

	if authProfileRes.profile != nil {
		existingPolicy.AuthProfileName = authProfileRes.profile.AuthProfileName
		if existingPolicy.Settings == nil {
			existingPolicy.Settings = make(map[string]interface{})
		}
		existingPolicy.Settings["/Core/Authentication/AuthenticationRulesDefaultProfileId"] = authProfileRes.profile.AuthProfileID
	}

	if updatePolicy.Settings != nil {
		for key, value := range updatePolicy.Settings {
			existingPolicy.Settings[key] = value
		}
	}

	// Update policy links
	for i, policyLink := range policyLinks {
		policySet, ok := policyLink["PolicySet"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse policy set from policy link - [%v]", policyLink)
		}
		policySet = policySet[len("/Policy/"):]
		if policySet == updatePolicy.PolicyName {
			if !isActive {
				policyLinks[i]["LinkType"] = "Inactive"
			} else {
				if len(roleIDsRes.ids) > 0 {
					policyLinks[i]["LinkType"] = "Role"
					policyLinks[i]["Params"] = roleIDsRes.ids
				} else {
					policyLinks[i]["LinkType"] = "Global"
				}
			}
		}
	}
	policyBlock := map[string]interface{}{
		"plinks": policyLinks,
		"policy": map[string]interface{}{
			"Path":        fmt.Sprintf("/Policy/%s", updatePolicy.PolicyName),
			"Version":     1,
			"Description": existingPolicy.Description,
			"Settings":    existingPolicy.Settings,
			"RevStamp":    existingPolicy.RevStamp,
			"Newpolicy":   "false",
		},
	}
	response, err := s.postOperation()(context.Background(), savePolicyURL, policyBlock)
	if err != nil {
		s.Logger.Error("Error updating identity policy: %s", err.Error())
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update identity policy - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to update identity policy - [%v]", result)
	}
	return existingPolicy, nil
}

// DeletePolicy deletes an identity policy.
func (s *IdsecIdentityPoliciesService) DeletePolicy(deletePolicy *policymodels.IdsecIdentityDeletePolicy) error {
	s.Logger.Debug("Deleting identity policy")
	policySet := deletePolicy.PolicyName
	if !strings.HasPrefix(policySet, "/Policy/") {
		policySet = fmt.Sprintf("/Policy/%s", deletePolicy.PolicyName)
	}
	response, err := s.postOperation()(context.Background(), deletePolicyURL, map[string]interface{}{
		"path": policySet,
	})
	if err != nil {
		s.Logger.Error("Error deleting identity policy: %s", err.Error())
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete identity policy - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return fmt.Errorf("failed to delete identity policy - [%v]", result)
	}
	return nil
}

// Policy retrieves an identity policy by its ID.
func (s *IdsecIdentityPoliciesService) Policy(getPolicy *policymodels.IdsecIdentityGetPolicy) (*policymodels.IdsecIdentityPolicy, error) {
	s.Logger.Debug("Retrieving identity policy")

	policySet := getPolicy.PolicyName
	if !strings.HasPrefix(policySet, "/Policy/") {
		policySet = fmt.Sprintf("/Policy/%s", getPolicy.PolicyName)
	}

	// Channels for parallel operations
	type policyLinksResult struct {
		links []map[string]interface{}
		err   error
	}
	type policyDataResult struct {
		data map[string]interface{}
		err  error
	}

	policyLinksChan := make(chan policyLinksResult, 1)
	policyDataChan := make(chan policyDataResult, 1)

	// Fetch policy links in parallel
	go func() {
		links, err := s.listPolicyLinks()
		policyLinksChan <- policyLinksResult{links: links, err: err}
	}()

	// Fetch policy data in parallel
	go func() {
		response, err := s.postOperation()(context.Background(), getPolicyURL, map[string]interface{}{
			"name": policySet,
		})
		if err != nil {
			s.Logger.Error("Error retrieving identity policy: %s", err.Error())
			policyDataChan <- policyDataResult{err: err}
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				common.GlobalLogger.Warning("Error closing response body")
			}
		}(response.Body)

		if response.StatusCode != http.StatusOK {
			policyDataChan <- policyDataResult{err: fmt.Errorf("failed to retrieve identity policy - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))}
			return
		}

		var result map[string]interface{}
		err = json.NewDecoder(response.Body).Decode(&result)
		if err != nil {
			policyDataChan <- policyDataResult{err: err}
			return
		}

		if res, ok := result["success"].(bool); !ok || !res {
			policyDataChan <- policyDataResult{err: fmt.Errorf("failed to retrieve identity policy - [%v]", result)}
			return
		}

		policyData, ok := result["Result"].(map[string]interface{})
		if !ok {
			policyDataChan <- policyDataResult{err: fmt.Errorf("failed to parse identity policy data - [%v]", result)}
			return
		}

		policyDataChan <- policyDataResult{data: policyData, err: nil}
	}()

	// Wait for both operations
	policyLinksRes := <-policyLinksChan
	policyDataRes := <-policyDataChan

	if policyLinksRes.err != nil {
		return nil, policyLinksRes.err
	}
	if policyDataRes.err != nil {
		return nil, policyDataRes.err
	}

	policyLinks := policyLinksRes.links
	policyData := policyDataRes.data

	// Extract role IDs from policy links
	roleIDs := []string{}
	policyStatus := policymodels.PolicyStatusActive
	for _, policyLink := range policyLinks {
		policyName, ok := policyLink["PolicySet"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse policy name from policy link - [%v]", policyLink)
		}
		linkType, ok := policyLink["LinkType"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse link type from policy link - [%v]", policyLink)
		}
		policyName = policyName[len("/Policy/"):]
		if policyName == getPolicy.PolicyName {
			switch linkType {
			case "Role":
				if params, ok := policyLink["Params"].([]interface{}); ok {
					for _, param := range params {
						if roleID, ok := param.(string); ok {
							roleIDs = append(roleIDs, roleID)
						}
					}
				}
			case "Inactive":
				policyStatus = policymodels.PolicyStatusInactive
			}
			break
		}
	}

	// Channels for parallel role and auth profile resolution
	type roleNamesResult struct {
		names []string
		err   error
	}
	type authProfileResult struct {
		name string
		err  error
	}

	roleNamesChan := make(chan roleNamesResult, 1)
	authProfileChan := make(chan authProfileResult, 1)

	// Resolve role IDs to names in parallel
	go func() {
		roleNames := make([]string, len(roleIDs))
		errChan := make(chan error, len(roleIDs))
		nameChan := make(chan struct {
			index int
			name  string
		}, len(roleIDs))

		for i, roleID := range roleIDs {
			go func(index int, id string) {
				role, err := s.RolesService.Role(&rolesmodels.IdsecIdentityGetRole{
					RoleID: id,
				})
				if err != nil {
					errChan <- err
					return
				}
				nameChan <- struct {
					index int
					name  string
				}{index: index, name: role.RoleName}
			}(i, roleID)
		}

		// Collect results
		for i := 0; i < len(roleIDs); i++ {
			select {
			case err := <-errChan:
				roleNamesChan <- roleNamesResult{err: err}
				return
			case result := <-nameChan:
				roleNames[result.index] = result.name
			}
		}

		roleNamesChan <- roleNamesResult{names: roleNames, err: nil}
	}()

	// Resolve auth profile in parallel
	go func() {
		settings, ok := policyData["Settings"].(map[string]interface{})
		if !ok {
			authProfileChan <- authProfileResult{name: "", err: nil}
			return
		}

		authProfileID, ok := settings["/Core/Authentication/AuthenticationRulesDefaultProfileId"].(string)
		if !ok {
			authProfileChan <- authProfileResult{name: "", err: nil}
			return
		}

		authProfile, err := s.AuthProfileService.AuthProfile(&authprofilesmodels.IdsecIdentityGetAuthProfile{
			AuthProfileID: authProfileID,
		})
		if err != nil {
			authProfileChan <- authProfileResult{err: err}
			return
		}

		authProfileChan <- authProfileResult{name: authProfile.AuthProfileName, err: nil}
	}()

	// Wait for role names and auth profile
	roleNamesRes := <-roleNamesChan
	authProfileRes := <-authProfileChan

	if roleNamesRes.err != nil {
		return nil, roleNamesRes.err
	}
	if authProfileRes.err != nil {
		return nil, authProfileRes.err
	}

	// Build policy info
	policyInfo := &policymodels.IdsecIdentityPolicy{}
	policyInfo.PolicyName = strings.TrimPrefix(policySet, "/Policy/")
	policyInfo.PolicyStatus = policyStatus
	policyInfo.RevStamp, _ = policyData["RevStamp"].(string)
	policyInfo.Description, _ = policyData["Description"].(string)
	policyInfo.RoleNames = roleNamesRes.names
	policyInfo.AuthProfileName = authProfileRes.name
	if settings, ok := policyData["Settings"].(map[string]interface{}); ok {
		policyInfo.Settings = settings
	}

	return policyInfo, nil
}

// ListPolicies lists all identity policies with optional filtering.
func (s *IdsecIdentityPoliciesService) ListPolicies() ([]*policymodels.IdsecIdentityPolicyInfo, error) {
	policyLinks, err := s.listPolicyLinks()
	if err != nil {
		return nil, err
	}
	policies := []*policymodels.IdsecIdentityPolicyInfo{}
	for _, policyLink := range policyLinks {
		policyName, ok := policyLink["PolicySet"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse policy name from policy link - [%v]", policyLink)
		}
		policyName = policyName[len("/Policy/"):]
		description, _ := policyLink["Description"].(string)
		linkType, ok := policyLink["LinkType"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to parse link type from policy link - [%v]", policyLink)
		}
		policyStatus := policymodels.PolicyStatusActive
		if linkType == "Inactive" {
			policyStatus = policymodels.PolicyStatusInactive
		}
		policies = append(policies, &policymodels.IdsecIdentityPolicyInfo{
			PolicyName:   policyName,
			PolicyStatus: policyStatus,
			Description:  description,
		})
	}
	return policies, nil
}

// ListPoliciesBy lists identity policies based on provided filters.
func (s *IdsecIdentityPoliciesService) ListPoliciesBy(filters *policymodels.IdsecIdentityPoliciesFilters) ([]*policymodels.IdsecIdentityPolicyInfo, error) {
	allPolicies, err := s.ListPolicies()
	if err != nil {
		return nil, err
	}
	filteredPolicies := []*policymodels.IdsecIdentityPolicyInfo{}
	for _, policy := range allPolicies {
		matches := true
		if len(filters.PolicyNames) > 0 {
			nameMatch := false
			for _, filterName := range filters.PolicyNames {
				if policy.PolicyName == filterName {
					nameMatch = true
					break
				}
			}
			if !nameMatch {
				matches = false
			}
		}
		if filters.PolicyStatus != "" {
			if policy.PolicyStatus != filters.PolicyStatus {
				matches = false
			}
		}
		if matches {
			filteredPolicies = append(filteredPolicies, policy)
		}
	}
	return filteredPolicies, nil
}

// PoliciesStats retrieves statistics related to identity policies.
func (s *IdsecIdentityPoliciesService) PoliciesStats() (*policymodels.IdsecIdentityPoliciesStats, error) {
	allPolicies, err := s.ListPolicies()
	if err != nil {
		return nil, err
	}
	stats := &policymodels.IdsecIdentityPoliciesStats{
		PoliciesCount:         len(allPolicies),
		PoliciesCountByStatus: make(map[string]int),
	}
	for _, policy := range allPolicies {
		if _, ok := stats.PoliciesCountByStatus[policy.PolicyStatus]; !ok {
			stats.PoliciesCountByStatus[policy.PolicyStatus] = 0
		}
		stats.PoliciesCountByStatus[policy.PolicyStatus]++
	}
	return stats, nil
}

// ServiceConfig returns the service configuration for the IdsecIdentityPoliciesService.
func (s *IdsecIdentityPoliciesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
