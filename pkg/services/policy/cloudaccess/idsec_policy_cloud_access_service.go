package cloudaccess

import (
	"fmt"
	"reflect"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	cloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
	policycommon "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

const (
	policyStatusActiveRetryCount = 10
)

// IdsecPolicyCloudAccessPolicyPage represents a page of Cloud Access policies.
type IdsecPolicyCloudAccessPolicyPage = common.IdsecPage[cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy]

// IdsecPolicyCloudAccessService exposes Cloud Access policy operations over the shared Policy base service.
type IdsecPolicyCloudAccessService struct {
	services.IdsecService
	*services.IdsecBaseService
	baseService *policycommon.IdsecPolicyBaseService
}

// NewIdsecPolicyCloudAccessService creates a new instance of IdsecPolicyCloudAccessService with the provided authenticators.
func NewIdsecPolicyCloudAccessService(authenticators ...auth.IdsecAuth) (*IdsecPolicyCloudAccessService, error) {
	cloudAccessService := &IdsecPolicyCloudAccessService{}
	var serviceInterface services.IdsecService = cloudAccessService
	baseService, err := services.NewIdsecBaseService(serviceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	cloudAccessService.IdsecBaseService = baseService
	cloudAccessService.baseService, err = policycommon.NewIdsecPolicyBaseService(
		ispAuth,
	)
	if err != nil {
		return nil, err
	}
	return cloudAccessService, nil
}

func (s *IdsecPolicyCloudAccessService) serializeTargets(policy *cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, policyJSON map[string]interface{}) error {
	var err error
	policy.Targets.ClearTargetsFromData(policyJSON["targets"].(map[string]interface{}))
	policyJSON["targets"], err = policy.Targets.SerializeTargets()
	return err
}

func (s *IdsecPolicyCloudAccessService) deserializeTargets(policy *cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, policyJSON map[string]interface{}) error {
	return policy.Targets.DeserializeTargets(policyJSON["targets"].(map[string]interface{}))
}

// AddPolicy adds a new policy with the given information.
func (s *IdsecPolicyCloudAccessService) AddPolicy(addPolicy *cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy) (*cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, error) {
	s.Logger.Info("Adding new policy [%s]", addPolicy.Metadata.Name)
	addPolicy.Metadata.PolicyEntitlement.TargetCategory = commonmodels.CategoryTypeCloudConsole
	if addPolicy.Metadata.PolicyTags == nil {
		addPolicy.Metadata.PolicyTags = make([]string, 0)
	}
	policyJSON, err := common.SerializeJSONCamel(addPolicy)
	if err != nil {
		return nil, err
	}
	err = s.serializeTargets(addPolicy, policyJSON)
	if err != nil {
		return nil, err
	}
	policyResp, err := s.baseService.BaseAddPolicy(policyJSON)
	if err != nil {
		return nil, err
	}
	retryCount := 0
	for {
		policy, err := s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
			PolicyID: policyResp.PolicyID,
		})
		if err != nil {
			return nil, err
		}
		if policy.Metadata.Status.Status == policycommonmodels.StatusTypeActive {
			break
		}
		if policy.Metadata.Status.Status == policycommonmodels.StatusTypeError {
			return nil, fmt.Errorf("policy [%s] is in error state: %s", policyResp.PolicyID, policy.Metadata.Status.Status)
		}
		if retryCount >= policyStatusActiveRetryCount {
			s.Logger.Warning("Policy [%s] is not active after 10 retries, "+
				"might indicate an issue, moving on regardless", policyResp.PolicyID)
			break
		}
		retryCount++
	}
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: policyResp.PolicyID,
	})
}

// Policy retrieves a policy by its ID.
func (s *IdsecPolicyCloudAccessService) Policy(policyRequest *policycommonmodels.IdsecPolicyGetPolicyRequest) (*cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, error) {
	s.Logger.Info("Retrieving policy [%s]", policyRequest.PolicyID)
	respType := reflect.TypeOf(cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{})
	policyJSON, err := s.baseService.BasePolicy(policyRequest.PolicyID, &respType)
	if err != nil {
		return nil, err
	}
	var cloudAccessPolicy cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy
	err = mapstructure.Decode(policyJSON, &cloudAccessPolicy)
	if err != nil {
		return nil, err
	}
	err = s.deserializeTargets(&cloudAccessPolicy, policyJSON)
	if err != nil {
		return nil, err
	}
	return &cloudAccessPolicy, nil
}

// UpdatePolicy edits an existing policy with the given information.
func (s *IdsecPolicyCloudAccessService) UpdatePolicy(updatePolicy *cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy) (*cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, error) {
	s.Logger.Info("Updating policy [%s]", updatePolicy.Metadata.PolicyID)
	policyJSON, err := common.SerializeJSONCamel(updatePolicy)
	if err != nil {
		return nil, err
	}
	err = s.serializeTargets(updatePolicy, policyJSON)
	if err != nil {
		return nil, err
	}
	err = s.baseService.BaseUpdatePolicy(updatePolicy.Metadata.PolicyID, policyJSON)
	if err != nil {
		return nil, err
	}
	retryCount := 0
	for {
		policy, err := s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
			PolicyID: updatePolicy.Metadata.PolicyID,
		})
		if err != nil {
			return nil, err
		}
		if policy.Metadata.Status.Status == policycommonmodels.StatusTypeActive {
			break
		}
		if policy.Metadata.Status.Status == policycommonmodels.StatusTypeError {
			return nil, fmt.Errorf("policy [%s] is in error state: %s", updatePolicy.Metadata.PolicyID, policy.Metadata.Status.Status)
		}
		if retryCount >= policyStatusActiveRetryCount {
			s.Logger.Warning("Policy [%s] is not active after 10 retries, "+
				"might indicate an issue, moving on regardless", updatePolicy.Metadata.PolicyID)
			break
		}
		retryCount++
	}
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: updatePolicy.Metadata.PolicyID,
	})
}

// ListPolicies retrieves all policies.
func (s *IdsecPolicyCloudAccessService) ListPolicies() (<-chan *IdsecPolicyCloudAccessPolicyPage, error) {
	s.Logger.Info("Listing all policies")
	policyPagesWithType := make(chan *IdsecPolicyCloudAccessPolicyPage)
	go func() {
		filters := policycommonmodels.NewIdsecPolicyFilters()
		filters.TargetCategory = []string{commonmodels.CategoryTypeCloudConsole}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			cloudAccessPolicies := IdsecPolicyCloudAccessPolicyPage{Items: make([]*cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var cloudAccessPolicy cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy
				err = mapstructure.Decode(*policy, &cloudAccessPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode policy page: %v", err)
					continue
				}
				cloudAccessPolicies.Items[idx] = &cloudAccessPolicy
			}
			policyPagesWithType <- &cloudAccessPolicies
		}
	}()
	return policyPagesWithType, nil
}

// ListPoliciesBy retrieves policies based on the provided filters.
func (s *IdsecPolicyCloudAccessService) ListPoliciesBy(filters *cloudaccessmodels.IdsecPolicyCloudAccessFilters) (<-chan *IdsecPolicyCloudAccessPolicyPage, error) {
	s.Logger.Info("Listing policies by filter")
	policyPagesWithType := make(chan *IdsecPolicyCloudAccessPolicyPage)
	go func() {
		if filters == nil {
			filters = &cloudaccessmodels.IdsecPolicyCloudAccessFilters{
				IdsecPolicyFilters: *policycommonmodels.NewIdsecPolicyFilters(),
			}
		}
		filters.TargetCategory = []string{commonmodels.CategoryTypeCloudConsole}
		policyPages, err := s.baseService.BaseListPolicies(&filters.IdsecPolicyFilters)
		if err != nil {
			s.Logger.Error("Failed to list policies by filter: %v", err)
			close(policyPagesWithType)
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			cloudAccessPolicies := IdsecPolicyCloudAccessPolicyPage{Items: make([]*cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var cloudAccessPolicy cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy
				err = mapstructure.Decode(*policy, &cloudAccessPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode policy page: %v", err)
					continue
				}
				cloudAccessPolicies.Items[idx] = &cloudAccessPolicy
			}
			policyPagesWithType <- &cloudAccessPolicies
		}
	}()
	return policyPagesWithType, nil
}

// DeletePolicy deletes a policy by its ID.
func (s *IdsecPolicyCloudAccessService) DeletePolicy(deletePolicy *policycommonmodels.IdsecPolicyDeletePolicyRequest) error {
	s.Logger.Info("Deleting policy [%s]", deletePolicy.PolicyID)
	return s.baseService.BaseDeletePolicy(deletePolicy.PolicyID)
}

// PolicyStatus retrieves the status of a policy by its ID or name.
func (s *IdsecPolicyCloudAccessService) PolicyStatus(getPolicyStatus *policycommonmodels.IdsecPolicyGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats calculates policies statistics.
func (s *IdsecPolicyCloudAccessService) PoliciesStats() (*policycommonmodels.IdsecPolicyStatistics, error) {
	s.Logger.Info("Calculating policies statistics")
	filters := policycommonmodels.NewIdsecPolicyFilters()
	filters.TargetCategory = []string{commonmodels.CategoryTypeCloudConsole}
	return s.baseService.BasePoliciesStats(filters)
}

// ServiceConfig returns the service configuration for IdsecPolicyCloudAccessService.
func (s *IdsecPolicyCloudAccessService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
