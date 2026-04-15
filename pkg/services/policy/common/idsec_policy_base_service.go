package policy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"

	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

const (
	policiesURL = "/api/policies"
	policyURL   = "/api/policies/%s"
)

// IdsecPolicyBasePolicyPage is a page of Raw Policy items.
type IdsecPolicyBasePolicyPage = common.IdsecPage[map[string]interface{}]

// IdsecPolicyBaseService is the base service for managing Policy policies.
type IdsecPolicyBaseService struct {
	logger *common.IdsecLogger
	*services.IdsecISPBaseService
}

// NewIdsecPolicyBaseService creates a new instance of IdsecPolicyBaseService.
func NewIdsecPolicyBaseService(ispAuth *auth.IdsecISPAuth) (*IdsecPolicyBaseService, error) {
	policyService := &IdsecPolicyBaseService{
		logger: common.GetLogger("IdsecPolicyService", common.Unknown),
	}

	// Create ISP base service with refresh function that references the policy service
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "uap", ".", "", policyService.refreshPolicyAuth)
	if err != nil {
		return nil, err
	}

	policyService.IdsecISPBaseService = ispBaseService
	return policyService, nil
}

func (s *IdsecPolicyBaseService) refreshPolicyAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// BaseCreatePolicy creates a new policy.
func (s *IdsecPolicyBaseService) BaseCreatePolicy(createPolicy map[string]interface{}) (*policycommonmodels.IdsecPolicyResponse, error) {
	s.logger.Info("Creating new policy")
	response, err := s.ISPClient().Post(context.Background(), policiesURL, createPolicy)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Failed to close response body: %v", err)
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create policy - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	policyIDJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var policyResponse policycommonmodels.IdsecPolicyResponse
	err = mapstructure.Decode(policyIDJSON, &policyResponse)
	if err != nil {
		return nil, err
	}
	return &policyResponse, nil
}

// BasePolicy retrieves a policy by ID.
func (s *IdsecPolicyBaseService) BasePolicy(policyID string, schema *reflect.Type) (map[string]interface{}, error) {
	s.logger.Info("Retrieving policy [%s]", policyID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(policyURL, policyID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Failed to close response body: %v", err)
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve policy - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	policyJSON, err := common.DeserializeJSONSnakeSchema(response.Body, schema)
	if err != nil {
		return nil, err
	}
	return policyJSON.(map[string]interface{}), nil
}

// BaseUpdatePolicy updates an existing policy.
func (s *IdsecPolicyBaseService) BaseUpdatePolicy(policyID string, updatePolicy map[string]interface{}) error {
	s.logger.Info("Updating policy [%s]", policyID)
	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(policyURL, policyID), updatePolicy)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Failed to close response body: %v", err)
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update policy - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// BaseDeletePolicy deletes a policy by ID.
func (s *IdsecPolicyBaseService) BaseDeletePolicy(policyID string) error {
	s.logger.Info("Deleting policy [%s]", policyID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(policyURL, policyID), nil, nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Failed to close response body: %v", err)
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete policy - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// BaseListPolicies retrieves all policies with optional filters.
func (s *IdsecPolicyBaseService) BaseListPolicies(filters *policycommonmodels.IdsecPolicyFilters) (<-chan *IdsecPolicyBasePolicyPage, error) {
	s.logger.Info("Listing policies")
	if filters == nil {
		filters = policycommonmodels.NewIdsecPolicyFilters()
	}

	pageChannel := make(chan *IdsecPolicyBasePolicyPage)
	go func() {
		defer close(pageChannel)
		var nextToken string
		var prevToken string
		pageCount := 0

		for filters.MaxPages >= pageCount {

			pageCount++

			// Build query parameters
			request := policycommonmodels.IdsecPolicyGetAccessPoliciesRequest{
				Filters:   filters,
				NextToken: nextToken,
			}
			queryParams := request.BuildGetQueryParams()
			queryParamsJSON, err := common.SerializeJSONCamel(queryParams)
			if err != nil {
				s.logger.Error("Failed to serialize query parameters: %v", err)
				return
			}
			queryParamsJSONParams := make(map[string]string)
			for key, value := range queryParamsJSON {
				queryParamsJSONParams[key] = fmt.Sprintf("%v", value)
			}

			// Make API call
			s.logger.Info("Requesting policies with next_token [%s] [%v]", nextToken, queryParamsJSONParams)
			response, err := s.ISPClient().Get(context.Background(), policiesURL, queryParamsJSONParams)
			if err != nil {
				s.logger.Error("Failed to list policies: %v", err)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)

			// Check response status
			if response.StatusCode != http.StatusOK {
				s.logger.Error("Failed to list policies - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
				return
			}

			// Parse response
			resultJSON, err := common.DeserializeJSONSnake(response.Body)
			if err != nil {
				s.logger.Error("Failed to decode response: %v", err)
				return
			}
			policiesJSONs, ok := resultJSON.(map[string]interface{})["results"].([]interface{})
			if !ok {
				s.logger.Error("Response does not contain 'results' key")
				return
			}
			policiesJSONsOut := make([]*map[string]interface{}, len(policiesJSONs))
			for i, policyJSONInterface := range policiesJSONs {
				// Convert to snake_case
				policyJSON, ok := policyJSONInterface.(map[string]interface{})
				if !ok {
					continue
				}
				policiesJSONsOut[i] = &policyJSON
			}

			// Send page to channel
			pageChannel <- &IdsecPolicyBasePolicyPage{Items: policiesJSONsOut}

			// Update tokens
			tempNextToken, ok := resultJSON.(map[string]interface{})["next_token"].(string)
			if !ok {
				s.logger.Error("Response does not contain 'next_token' key or it is not a string")
				return
			}
			prevToken, nextToken = nextToken, tempNextToken

			// Break if no next token or pagination loop detected
			if nextToken == "" || nextToken == prevToken {
				if nextToken == prevToken {
					s.logger.Error("Pagination stuck: next_token did not change between requests")
				}
				break
			}
			if len(policiesJSONs) < queryParams.Limit {
				s.logger.Info("No more policies to retrieve, breaking pagination loop")
				break
			}
		}
	}()

	return pageChannel, nil
}

// BasePolicyByName retrieves a policy by its name.
func (s *IdsecPolicyBaseService) BasePolicyByName(policyName string) (map[string]interface{}, error) {
	s.logger.Info("Retrieving policy by name [%s]", policyName)
	filters := policycommonmodels.NewIdsecPolicyFilters()
	filters.TextSearch = policyName
	policies, err := s.BaseListPolicies(filters)
	if err != nil {
		return nil, err
	}

	for page := range policies {
		for _, policy := range page.Items {
			metadataJSON, ok := (*policy)["metadata"].(map[string]interface{})
			if !ok {
				continue
			}
			var metadata policycommonmodels.IdsecPolicyMetadata
			err = mapstructure.Decode(metadataJSON, &metadata)
			if err != nil {
				continue
			}
			if metadata.Name == policyName {
				return *policy, nil
			}
		}
	}
	return nil, fmt.Errorf("policy with name '%s' not found", policyName)
}

// BasePolicyStatus retrieves the status of a policy by its ID or name.
func (s *IdsecPolicyBaseService) BasePolicyStatus(policyID string, policyName string, schema *reflect.Type) (string, error) {
	s.logger.Info("Retrieving policy status for [%s] with name [%s]", policyID, policyName)
	var policy map[string]interface{}
	var err error
	if policyID != "" {
		policy, err = s.BasePolicy(policyID, schema)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve policy status for ID '%s' and name '%s': %w", policyID, policyName, err)
		}
	} else if policyName != "" {
		policy, err = s.BasePolicyByName(policyName)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve policy status for ID '%s' and name '%s': %w", policyID, policyName, err)
		}
	} else {
		return "", fmt.Errorf("either policyID or policyName must be provided to retrieve policy status")
	}
	metadataJSON, ok := policy["metadata"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("policy metadata not found for ID '%s' and name '%s'", policyID, policyName)
	}
	var metadata policycommonmodels.IdsecPolicyMetadata
	err = mapstructure.Decode(metadataJSON, &metadata)
	if err != nil {
		return "", fmt.Errorf("failed to decode policy metadata for ID '%s' and name '%s': %w", policyID, policyName, err)
	}
	return metadata.Status.Status, nil
}

// BasePoliciesStats retrieves statistics about policies.
func (s *IdsecPolicyBaseService) BasePoliciesStats(filters *policycommonmodels.IdsecPolicyFilters) (*policycommonmodels.IdsecPolicyStatistics, error) {
	policiesStats := &policycommonmodels.IdsecPolicyStatistics{
		PoliciesCount:            0,
		PoliciesCountPerStatus:   make(map[string]int),
		PoliciesCountPerProvider: make(map[string]int),
	}
	s.logger.Info("Retrieving policies stats")
	policies, err := s.BaseListPolicies(filters)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve policies stats: %w", err)
	}
	for page := range policies {
		for _, policy := range page.Items {
			policiesStats.PoliciesCount++
			metadataJSON, ok := (*policy)["metadata"].(map[string]interface{})
			if !ok {
				continue
			}
			var metadata policycommonmodels.IdsecPolicyMetadata
			err = mapstructure.Decode(metadataJSON, &metadata)
			if err != nil {
				continue
			}
			if _, ok = policiesStats.PoliciesCountPerStatus[metadata.Status.Status]; !ok {
				policiesStats.PoliciesCountPerStatus[metadata.Status.Status] = 0
			}
			if _, ok = policiesStats.PoliciesCountPerProvider[metadata.PolicyEntitlement.LocationType]; !ok {
				policiesStats.PoliciesCountPerProvider[metadata.PolicyEntitlement.LocationType] = 0
			}
			policiesStats.PoliciesCountPerStatus[metadata.Status.Status]++
			policiesStats.PoliciesCountPerProvider[metadata.PolicyEntitlement.LocationType]++
		}
	}
	return policiesStats, nil
}

// BaseWaitPolicyActive waits until the policy reaches Active status or until maxRetries is exceeded.
//
// Parameters:
//   - policyID: The unique identifier of the policy to monitor.
//   - schema: Pointer to a reflect.Type describing the policy structure for deserialization.
//   - maxRetries: Maximum number of retries before giving up.
//   - delaySeconds: Delay between retries in seconds.
//
// Returns an error if the policy enters an error state or retries are exhausted.
func (s *IdsecPolicyBaseService) BaseWaitPolicyActive(policyID string, schema *reflect.Type, maxRetries int, delaySeconds int) error { //nolint:revive
	if maxRetries < 0 {
		s.logger.Error("Policy [%s] is not active after [%d] retries, might indicate an issue, moving on regardless", policyID, maxRetries)
		return fmt.Errorf("policy [%s] is not active after [%d] retries", policyID, maxRetries)
	}

	var nonRetryableErr error
	tries := maxRetries + 1

	err := common.RetryCall(
		func() error {
			policy, err := s.BasePolicy(policyID, schema)
			if err != nil {
				nonRetryableErr = err
				return nil
			}

			metadataJSON, ok := policy["metadata"].(map[string]interface{})
			if !ok {
				nonRetryableErr = fmt.Errorf("policy metadata not found for ID '%s'", policyID)
				return nil
			}

			var metadata policycommonmodels.IdsecPolicyMetadata
			if err = mapstructure.Decode(metadataJSON, &metadata); err != nil {
				nonRetryableErr = err
				return nil
			}

			status := metadata.Status.Status
			if status == policycommonmodels.StatusTypeActive {
				return nil
			}

			if status == policycommonmodels.StatusTypeError {
				nonRetryableErr = fmt.Errorf("policy [%s] is in error state: %s", policyID, status)
				return nil
			}

			return fmt.Errorf("policy [%s] is not active yet: current status [%s]", policyID, status)
		},
		tries,
		delaySeconds,
		nil,
		1,
		0,
		nil,
	)
	if nonRetryableErr != nil {
		return nonRetryableErr
	}
	if err != nil {
		s.logger.Error("Policy [%s] is not active after [%d] retries, might indicate an issue, moving on regardless", policyID, maxRetries)
		return fmt.Errorf("policy [%s] is not active after [%d] retries", policyID, maxRetries)
	}
	return nil
}

// BaseCreatePolicyAndWait creates a new policy and waits for it to become Active, up to the provided retry limit.
//
// Parameters:
//   - createPolicy: Serialized policy payload map.
//   - schema: Pointer to a reflect.Type describing the policy structure for deserialization.
//   - maxRetries: Maximum number of retries before giving up.
//   - delaySeconds: Delay between retries in seconds.
//
// Returns the IdsecPolicyResponse containing PolicyID on success and waits until active or retries exhausted.
func (s *IdsecPolicyBaseService) BaseCreatePolicyAndWait(createPolicy map[string]interface{}, schema *reflect.Type, maxRetries int, delaySeconds int) (*policycommonmodels.IdsecPolicyResponse, error) { //nolint:revive
	resp, err := s.BaseCreatePolicy(createPolicy)
	if err != nil {
		return nil, err
	}
	if err = s.BaseWaitPolicyActive(resp.PolicyID, schema, maxRetries, delaySeconds); err != nil {
		return nil, err
	}
	return resp, nil
}
