package syncpolicies

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	syncpoliciesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies/models"
)

const (
	// maxRetries is the maximum number of attempts for the GET request after a successful POST.
	maxRetries = 4

	// baseDelay is the initial delay in seconds between retry attempts.
	baseDelay = 2

	// maxDelay is the maximum delay in seconds between retry attempts.
	maxDelay = 30

	// backoff is the multiplier applied to the delay after each failed attempt.
	backoff = 2
)

const (
	sechubURL      = "/api/policies"
	policyURL      = "/api/policies/%s"
	policyStateURL = "/api/policies/%s/state"
)

// IdsecSecHubSyncPoliciesPage is a page of IdsecSecHubPolicy items.
type IdsecSecHubSyncPoliciesPage = common.IdsecPage[syncpoliciesmodels.IdsecSecHubPolicy]

// IdsecSecHubSyncPoliciesService is the service for retrieve Secrets Hub Sync Policies
type IdsecSecHubSyncPoliciesService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSecHubSyncPoliciesService creates a new instance of IdsecSecHubSyncPoliciesService.
func NewIdsecSecHubSyncPoliciesService(authenticators ...auth.IdsecAuth) (*IdsecSecHubSyncPoliciesService, error) {
	syncPoliciesService := &IdsecSecHubSyncPoliciesService{}
	var syncPoliciesServiceInterface services.IdsecService = syncPoliciesService
	baseService, err := services.NewIdsecBaseService(syncPoliciesServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "secretshub", ".", "", syncPoliciesService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}

	syncPoliciesService.IdsecBaseService = baseService
	syncPoliciesService.IdsecISPBaseService = ispBaseService
	return syncPoliciesService, nil
}

func (s *IdsecSecHubSyncPoliciesService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSecHubSyncPoliciesService) getSyncPoliciesWithFilters(
	projection string,
	filter string,
) (<-chan *IdsecSecHubSyncPoliciesPage, error) {
	query := map[string]string{}
	if projection != "" {
		query["projection"] = projection
	}
	if filter != "" {
		query["filter"] = filter
	}
	results := make(chan *IdsecSecHubSyncPoliciesPage)
	go func() {
		defer close(results)
		for {
			response, err := s.ISPClient().Get(context.Background(), sechubURL, query)
			if err != nil {
				s.Logger.Error("Failed to list Sync Policies: %v", err)
				return
			}
			page, err := validateAndDecodeHTTPResponse[syncpoliciesmodels.IdsecSecHubSyncPoliciesListResponse](response, http.StatusOK, "failed to list sync policies")
			if err != nil {
				s.Logger.Error("Failed to list Sync Policies: %v", err)
				return
			}
			results <- &IdsecSecHubSyncPoliciesPage{Items: page.Policies}
			if page.NextLink != "" {
				nextQuery, _ := url.Parse(page.NextLink)
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

// closeResponseBody closes an HTTP response body and logs a warning if the close fails.
func closeResponseBody(body io.ReadCloser) {
	if err := body.Close(); err != nil {
		common.GlobalLogger.Warning("Error closing response body")
	}
}

// checkHTTPStatus checks whether the response status matches the expected status code without
// closing the body, allowing callers that need to read the body afterwards to do so safely.
func checkHTTPStatus(response *http.Response, expectedStatus int, errMsg string) error {
	if response.StatusCode == expectedStatus {
		return nil
	}
	return fmt.Errorf("%s - [%d] - [%s]", errMsg, response.StatusCode, common.SerializeResponseToJSON(response.Body))
}

// validateHTTPResponse validates an HTTP response by checking for a specific expected status code.
func validateHTTPResponse(response *http.Response, expectedStatus int, errMsg string) error {
	defer closeResponseBody(response.Body)
	return checkHTTPStatus(response, expectedStatus, errMsg)
}

// validateAndDecodeHTTPResponse validates an HTTP response, deserializes the body, and decodes
// it directly into the target type T.
func validateAndDecodeHTTPResponse[T any](response *http.Response, expectedStatus int, errMsg string) (*T, error) {
	defer closeResponseBody(response.Body)

	if err := checkHTTPStatus(response, expectedStatus, errMsg); err != nil {
		return nil, err
	}

	body, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var result T
	if err := mapstructure.Decode(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// isNotAlreadyDisabled checks if the error is not a 409 Conflict, because then the sync policy has been disabled.
//
// Example error: failed to delete sync policy - [409] - [{"code":"PLCY0006E","message":"Conflict with current policy state"}]
//
// Parameters:
//   - err: The error to check for conflict indicators.
//
// Returns true if the error does not represent a 409 Conflict.
func isNotAlreadyDisabled(err error) bool {
	return !strings.Contains(err.Error(), "409") && !strings.Contains(err.Error(), "Conflict")
}

// retryWithBackoff executes the given function with exponential backoff retry logic.
//
// This method wraps common.RetryCall with the service's default retry configuration
// and logging. It is used to retry transient failures for any operation (e.g., GET
// after POST, DELETE requests).
//
// Parameters:
//   - operation: A description of the operation being retried (used in log messages)
//   - resourceID: The ID of the resource being operated on (used in log messages)
//   - fn: The function to execute and retry on failure
//
// Returns nil on success, or the last error if all retries are exhausted.
func (s *IdsecSecHubSyncPoliciesService) retryWithBackoff(
	operation string,
	resourceID string,
	fn func() error,
) error {
	maxDelay := maxDelay
	return common.RetryCall(
		fn,
		maxRetries,
		baseDelay,
		&maxDelay,
		backoff,
		nil,
		func(err error, delay int) {
			s.Logger.Warning("%s failed for sync policy [%s]: %v. Retrying in %ds...",
				operation, resourceID, err, delay)
		},
	)
}

// mergeKnownPredefined overlays knownPredefined onto t when knownPredefined is not empty.
// Extended GET may omit predefined; Transformation.ID from the API response is preserved.
// This is necessary to align the Terraform state as the transformation.predefined input is not returned by the extended policy response
func mergeKnownPredefined(t syncpoliciesmodels.IdsecSecHubPolicyTransformation, knownPredefined string) syncpoliciesmodels.IdsecSecHubPolicyTransformation {
	if knownPredefined == "" {
		return t
	}
	return syncpoliciesmodels.IdsecSecHubPolicyTransformation{
		ID:         t.ID,
		Predefined: knownPredefined,
	}
}

// List returns a channel of IdsecSecHubSyncPoliciesPage containing all Sync Policies.
func (s *IdsecSecHubSyncPoliciesService) List(syncPolicies *syncpoliciesmodels.IdsecSecHubGetSyncPolicies) (<-chan *IdsecSecHubSyncPoliciesPage, error) {
	var projection string
	if syncPolicies.Projection != "" {
		projection = syncPolicies.Projection
	}
	return s.getSyncPoliciesWithFilters(
		projection,
		"",
	)
}

// ListBy returns a channel of IdsecSecHubSyncPoliciesPage containing secrets filtered by the given filters.
func (s *IdsecSecHubSyncPoliciesService) ListBy(syncPoliciesFilters *syncpoliciesmodels.IdsecSecHubSyncPoliciesFilters) (<-chan *IdsecSecHubSyncPoliciesPage, error) {
	var projection string
	if syncPoliciesFilters.Projection != "" {
		projection = syncPoliciesFilters.Projection
	}
	return s.getSyncPoliciesWithFilters(
		projection,
		syncPoliciesFilters.Filters,
	)
}

// Get returns an individual sync policy with Extended Projection response by default.
// When getSyncPolicy.Transformation.Predefined is non-empty, that value is merged onto the returned policy's
// Transformation (keeping Transformation.ID from the GET response) because the extended GET payload may omit predefined.
func (s *IdsecSecHubSyncPoliciesService) Get(
	getSyncPolicy *syncpoliciesmodels.IdsecSecHubGetSyncPolicy) (*syncpoliciesmodels.IdsecSecHubPolicy, error) {
	s.Logger.Info("Retrieving sync policy [%s]", getSyncPolicy.PolicyID)
	projection := getSyncPolicy.Projection
	if projection == "" {
		projection = syncpoliciesmodels.IdsecSecHubSyncPolicyProjectionExtend
	}
	query := map[string]string{
		"projection": projection,
	}
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(policyURL, getSyncPolicy.PolicyID), query)
	if err != nil {
		return nil, err
	}

	syncPolicy, err := validateAndDecodeHTTPResponse[syncpoliciesmodels.IdsecSecHubPolicy](response, http.StatusOK, "failed to get sync policy")
	if err != nil {
		return nil, err
	}
	syncPolicy.Transformation = mergeKnownPredefined(syncPolicy.Transformation, getSyncPolicy.Transformation.Predefined)

	return syncPolicy, nil
}

// Create creates a new sync policy and returns the extended GET representation via Get (see Get for response shape).
// When syncPolicy.Transformation.Predefined is non-empty, that value is merged onto the returned policy's
// Transformation (keeping Transformation.ID from the GET response) because the extended GET payload may omit predefined.
func (s *IdsecSecHubSyncPoliciesService) Create(syncPolicy *syncpoliciesmodels.IdsecSechubCreateSyncPolicy) (*syncpoliciesmodels.IdsecSecHubPolicy, error) {
	s.Logger.Info("Creating sync policy [%s]", syncPolicy.Name)
	createSyncPolicyJSON, err := common.SerializeJSONCamel(syncPolicy)
	if err != nil {
		return nil, err
	}
	response, err := s.ISPClient().Post(context.Background(), sechubURL, createSyncPolicyJSON)
	if err != nil {
		return nil, err
	}
	syncPolicyResponse, err := validateAndDecodeHTTPResponse[syncpoliciesmodels.IdsecSecHubPolicy](response, http.StatusCreated, "failed to create sync policy")
	if err != nil {
		return nil, err
	}
	getSyncPolicyRequest := &syncpoliciesmodels.IdsecSecHubGetSyncPolicy{
		PolicyID: syncPolicyResponse.ID,
	}
	if p := syncPolicy.Transformation.Predefined; p != "" {
		getSyncPolicyRequest.Transformation = syncpoliciesmodels.IdsecSecHubPolicyTransformation{
			Predefined: p,
		}
	}

	var syncPolicyExtendedResponse *syncpoliciesmodels.IdsecSecHubPolicy
	retryErr := s.retryWithBackoff("GET after Create", syncPolicyResponse.ID, func() error {
		var getErr error
		syncPolicyExtendedResponse, getErr = s.Get(getSyncPolicyRequest)
		return getErr
	})
	if retryErr != nil {
		msg := fmt.Sprintf("Error: %s . Failed to retrieve newly created sync policy [%s] after [%d] retries. If there is an issue with the secrets hub service, please use id [%s] to retrieve the created sync policy when the service becomes available again",
			retryErr.Error(),
			syncPolicyResponse.Name,
			maxRetries,
			syncPolicyResponse.ID)
		s.Logger.Error("%s", msg)
		return nil, fmt.Errorf("%s", msg)
	}

	s.Logger.Info("Sync policy created [%s]", syncPolicyExtendedResponse.ID)
	return syncPolicyExtendedResponse, nil
}

// SetState sets the state of a sync policy.
// https://api-docs.cyberark.com/docs/secretshub-api/by05aodbep6xy-set-sync-policy-state
func (s *IdsecSecHubSyncPoliciesService) SetState(
	setSyncPolicyState *syncpoliciesmodels.IdsecSecHubSetSyncPolicyState) error {
	s.Logger.Info("Setting sync policy state [%s] to [%s]", setSyncPolicyState.PolicyID, setSyncPolicyState.Action)
	bodyMap := map[string]string{
		"action": setSyncPolicyState.Action,
	}
	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(policyStateURL, setSyncPolicyState.PolicyID), bodyMap)
	if err != nil {
		return err
	}
	if err := validateHTTPResponse(response, http.StatusOK, "failed to delete sync policy"); err != nil {
		return err
	}
	return nil
}

// Delete disables and then deletes a specified sync policy based on the id
// https://api-docs.cyberark.com/docs/secretshub-api/lgbolpf4ka7oa-delete-sync-policy
func (s *IdsecSecHubSyncPoliciesService) Delete(syncPolicy *syncpoliciesmodels.IdsecSecHubDeleteSyncPolicy) error {
	state := syncpoliciesmodels.IdsecSecHubSetSyncPolicyState{
		PolicyID: syncPolicy.PolicyID,
		Action:   "disable",
	}
	// To delete a sync policy, it must first be disabled.
	s.Logger.Info("Setting sync policy [%s] state to disabled before deletion", state.PolicyID)
	err := s.SetState(&state)

	//If policy already disabled, we get a 409 error so just skip to delete
	if err != nil && isNotAlreadyDisabled(err) {
		s.Logger.Error("Error setting sync policy state to disabled before deletion: %s", err.Error())
		return err
	}

	s.Logger.Info("Deleting secret store sync policy [%s]", syncPolicy.PolicyID)
	deleteErr := s.retryWithBackoff("DELETE", syncPolicy.PolicyID, func() error {
		response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(policyURL, syncPolicy.PolicyID), nil, nil)
		if err != nil {
			return err
		}
		return validateHTTPResponse(response, http.StatusOK, "failed to delete sync policy")
	})
	if deleteErr != nil {
		s.Logger.Error("Error: %s . Failed to delete sync policy [%s] after [%d] retries", deleteErr.Error(), syncPolicy.PolicyID, maxRetries)
		return deleteErr
	}
	return nil
}

// Update Align with legacy terraform provider and do not allow updates to sync policies through this service.
// If updates are needed see SetState for state changes.
func (s *IdsecSecHubSyncPoliciesService) Update(syncPolicy *syncpoliciesmodels.IdsecSecHubUpdateSyncPolicy) (*syncpoliciesmodels.IdsecSecHubPolicy, error) {
	return nil, fmt.Errorf("updating the sync policy is not supported through terraform. Please consult with your CyberArk Administrator about updating policy with id [%s]", syncPolicy.ID)
}

// Stats retrieves statistics about sync policies.
func (s *IdsecSecHubSyncPoliciesService) Stats() (*syncpoliciesmodels.IdsecSecHubSyncPoliciesStats, error) {
	s.Logger.Info("Retrieving sync policy stats")
	var projection = syncpoliciesmodels.IdsecSecHubGetSyncPolicies{
		Projection: syncpoliciesmodels.IdsecSecHubSyncPolicyProjectionRegular,
	}
	syncPoliciesChan, err := s.List(&projection)
	if err != nil {
		return nil, err
	}
	syncPolicies := make([]*syncpoliciesmodels.IdsecSecHubPolicy, 0)
	for page := range syncPoliciesChan {
		syncPolicies = append(syncPolicies, page.Items...)
	}
	var syncPoliciesStats syncpoliciesmodels.IdsecSecHubSyncPoliciesStats
	syncPoliciesStats.SyncPoliciesCount = len(syncPolicies)
	syncPoliciesStats.SyncPoliciesCountByCreator = make(map[string]int)
	for _, syncPolicy := range syncPolicies {
		if _, ok := syncPoliciesStats.SyncPoliciesCountByCreator[syncPolicy.CreatedBy]; !ok {
			syncPoliciesStats.SyncPoliciesCountByCreator[syncPolicy.CreatedBy] = 0
		}
		syncPoliciesStats.SyncPoliciesCountByCreator[syncPolicy.CreatedBy]++
	}
	return &syncPoliciesStats, nil
}

// ServiceConfig returns the service configuration for the IdsecSecHubSyncPoliciesService.
func (s *IdsecSecHubSyncPoliciesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
