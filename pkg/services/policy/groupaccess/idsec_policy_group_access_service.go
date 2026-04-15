package groupaccess

import (
	"fmt"
	"reflect"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	policycommon "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/models"
)

const (
	policyStatusActiveRetryCount = 100
	delayTimeInSeconds           = 3
)

// IdsecPolicyGroupAccessPolicyPage represents a page of Group assignment policies.
type IdsecPolicyGroupAccessPolicyPage = common.IdsecPage[groupaccessmodels.IdsecPolicyGroupAccessPolicy]

// IdsecPolicyGroupAccessService exposes Group assignment policy operations over the shared Policy base service.
type IdsecPolicyGroupAccessService struct {
	*services.IdsecBaseService
	baseService *policycommon.IdsecPolicyBaseService
}

// NewIdsecPolicyGroupAccessService creates a new instance of IdsecPolicyGroupAccessService with the provided authenticators.
func NewIdsecPolicyGroupAccessService(authenticators ...auth.IdsecAuth) (*IdsecPolicyGroupAccessService, error) {
	groupAccessService := &IdsecPolicyGroupAccessService{}
	var serviceInterface services.IdsecService = groupAccessService
	baseService, err := services.NewIdsecBaseService(serviceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	groupAccessService.IdsecBaseService = baseService
	groupAccessService.baseService, err = policycommon.NewIdsecPolicyBaseService(
		ispAuth,
	)
	if err != nil {
		return nil, err
	}
	return groupAccessService, nil
}

// CreatePolicy creates a new policy with the given information.
func (s *IdsecPolicyGroupAccessService) CreatePolicy(createPolicy *groupaccessmodels.IdsecPolicyGroupAccessPolicy) (*groupaccessmodels.IdsecPolicyGroupAccessPolicy, error) {
	s.Logger.Info("Creating new group assignment policy [%s]", createPolicy.Metadata.Name)
	createPolicy.Metadata.PolicyEntitlement.TargetCategory = commonmodels.CategoryTypeGroupAccess
	if createPolicy.Metadata.PolicyTags == nil {
		createPolicy.Metadata.PolicyTags = make([]string, 0)
	}
	policyJSON, err := common.SerializeJSONCamel(createPolicy)
	if err != nil {
		return nil, err
	}
	respType := reflect.TypeOf(groupaccessmodels.IdsecPolicyGroupAccessPolicy{})
	policyResp, err := s.baseService.BaseCreatePolicyAndWait(policyJSON, &respType, policyStatusActiveRetryCount, delayTimeInSeconds)
	if err != nil {
		return nil, err
	}
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: policyResp.PolicyID,
	})
}

// Policy retrieves a policy by its ID.
func (s *IdsecPolicyGroupAccessService) Policy(policyRequest *policycommonmodels.IdsecPolicyGetPolicyRequest) (*groupaccessmodels.IdsecPolicyGroupAccessPolicy, error) {
	s.Logger.Info("Retrieving group assignment policy [%s]", policyRequest.PolicyID)
	respType := reflect.TypeOf(groupaccessmodels.IdsecPolicyGroupAccessPolicy{})
	policyJSON, err := s.baseService.BasePolicy(policyRequest.PolicyID, &respType)
	if err != nil {
		return nil, err
	}
	var groupAccessPolicy groupaccessmodels.IdsecPolicyGroupAccessPolicy
	err = mapstructure.Decode(policyJSON, &groupAccessPolicy)
	if err != nil {
		return nil, err
	}
	return &groupAccessPolicy, nil
}

// UpdatePolicy edits an existing policy with the given information.
func (s *IdsecPolicyGroupAccessService) UpdatePolicy(updatePolicy *groupaccessmodels.IdsecPolicyGroupAccessPolicy) (*groupaccessmodels.IdsecPolicyGroupAccessPolicy, error) {
	s.Logger.Info("Updating group assignment policy [%s]", updatePolicy.Metadata.PolicyID)
	policyJSON, err := common.SerializeJSONCamel(updatePolicy)
	if err != nil {
		return nil, err
	}
	err = s.baseService.BaseUpdatePolicy(updatePolicy.Metadata.PolicyID, policyJSON)
	if err != nil {
		return nil, err
	}
	respType := reflect.TypeOf(groupaccessmodels.IdsecPolicyGroupAccessPolicy{})
	if err = s.baseService.BaseWaitPolicyActive(updatePolicy.Metadata.PolicyID, &respType, policyStatusActiveRetryCount, delayTimeInSeconds); err != nil {
		return nil, err
	}
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: updatePolicy.Metadata.PolicyID,
	})
}

// ListPolicies retrieves all policies.
func (s *IdsecPolicyGroupAccessService) ListPolicies() (<-chan *IdsecPolicyGroupAccessPolicyPage, error) {
	s.Logger.Info("Listing all group assignment policies")
	policyPagesWithType := make(chan *IdsecPolicyGroupAccessPolicyPage)
	go func() {
		filters := policycommonmodels.NewIdsecPolicyFilters()
		filters.TargetCategory = []string{commonmodels.CategoryTypeGroupAccess}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			groupAccessPolicies := IdsecPolicyGroupAccessPolicyPage{Items: make([]*groupaccessmodels.IdsecPolicyGroupAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var groupAccessPolicy groupaccessmodels.IdsecPolicyGroupAccessPolicy
				err = mapstructure.Decode(*policy, &groupAccessPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode group assignment policy page: %v", err)
					continue
				}
				groupAccessPolicies.Items[idx] = &groupAccessPolicy
			}
			policyPagesWithType <- &groupAccessPolicies
		}
	}()
	return policyPagesWithType, nil
}

// ListPoliciesBy retrieves policies based on the provided filters.
func (s *IdsecPolicyGroupAccessService) ListPoliciesBy(filters *groupaccessmodels.IdsecPolicyGroupAccessFilters) (<-chan *IdsecPolicyGroupAccessPolicyPage, error) {
	s.Logger.Info("Listing group assignment policies by filter")
	policyPagesWithType := make(chan *IdsecPolicyGroupAccessPolicyPage)
	go func() {
		if filters == nil {
			filters = &groupaccessmodels.IdsecPolicyGroupAccessFilters{
				IdsecPolicyFilters: *policycommonmodels.NewIdsecPolicyFilters(),
			}
		}
		filters.TargetCategory = []string{commonmodels.CategoryTypeGroupAccess}
		policyPages, err := s.baseService.BaseListPolicies(&filters.IdsecPolicyFilters)
		if err != nil {
			s.Logger.Error("Failed to list group assignment policies by filter: %v", err)
			close(policyPagesWithType)
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			groupAccessPolicies := IdsecPolicyGroupAccessPolicyPage{Items: make([]*groupaccessmodels.IdsecPolicyGroupAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var groupAccessPolicy groupaccessmodels.IdsecPolicyGroupAccessPolicy
				err = mapstructure.Decode(*policy, &groupAccessPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode group assignment policy page: %v", err)
					continue
				}
				groupAccessPolicies.Items[idx] = &groupAccessPolicy
			}
			policyPagesWithType <- &groupAccessPolicies
		}
	}()
	return policyPagesWithType, nil
}

// DeletePolicy deletes a policy by its ID.
func (s *IdsecPolicyGroupAccessService) DeletePolicy(deletePolicy *policycommonmodels.IdsecPolicyDeletePolicyRequest) error {
	s.Logger.Info("Deleting group assignment policy [%s]", deletePolicy.PolicyID)
	return s.baseService.BaseDeletePolicy(deletePolicy.PolicyID)
}

// PolicyStatus retrieves the status of a policy by its ID or name.
func (s *IdsecPolicyGroupAccessService) PolicyStatus(getPolicyStatus *policycommonmodels.IdsecPolicyGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving group assignment policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(groupaccessmodels.IdsecPolicyGroupAccessPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats calculates policies statistics.
func (s *IdsecPolicyGroupAccessService) PoliciesStats() (*policycommonmodels.IdsecPolicyStatistics, error) {
	s.Logger.Info("Calculating group assignment policies statistics")
	filters := policycommonmodels.NewIdsecPolicyFilters()
	filters.TargetCategory = []string{commonmodels.CategoryTypeGroupAccess}
	return s.baseService.BasePoliciesStats(filters)
}

// ServiceConfig returns the service configuration for IdsecPolicyGroupAccessService.
func (s *IdsecPolicyGroupAccessService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

// AddExtraContextField adds a custom context field to telemetry data.
// Delegates to the base service which has the ISP client with telemetry support.
func (s *IdsecPolicyGroupAccessService) AddExtraContextField(name, shortName, value string) error {
	return s.baseService.AddExtraContextField(name, shortName, value)
}

// ClearExtraContext removes all extra context fields from telemetry data.
// Delegates to the base service which has the ISP client with telemetry support.
func (s *IdsecPolicyGroupAccessService) ClearExtraContext() error {
	return s.baseService.ClearExtraContext()
}
