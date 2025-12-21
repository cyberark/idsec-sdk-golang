package policy

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	policy "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"

	"reflect"
)

// IdsecPolicyPolicyPage represents a page of common policies in the Policy service.
type IdsecPolicyPolicyPage = common.IdsecPage[policycommonmodels.IdsecPolicyCommonAccessPolicy]

// IdsecPolicyService represents the Policy service.
type IdsecPolicyService struct {
	services.IdsecService
	*services.IdsecBaseService
	baseService *policy.IdsecPolicyBaseService
}

// NewIdsecPolicyService creates a new instance of IdsecPolicyService with the provided authenticators.
func NewIdsecPolicyService(authenticators ...auth.IdsecAuth) (*IdsecPolicyService, error) {
	policyService := &IdsecPolicyService{}
	var policyServiceInterface services.IdsecService = policyService
	baseService, err := services.NewIdsecBaseService(policyServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	policyService.IdsecBaseService = baseService
	policyService.baseService, err = policy.NewIdsecPolicyBaseService(
		ispAuth,
	)
	if err != nil {
		return nil, err
	}
	return policyService, nil
}

// ListPolicies retrieves all policies.
func (s *IdsecPolicyService) ListPolicies() (<-chan *IdsecPolicyPolicyPage, error) {
	s.Logger.Info("Listing all policies")
	policyPagesWithType := make(chan *IdsecPolicyPolicyPage)
	go func() {
		filters := policycommonmodels.NewIdsecPolicyFilters()
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			policies := IdsecPolicyPolicyPage{Items: make([]*policycommonmodels.IdsecPolicyCommonAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var commonPolicy policycommonmodels.IdsecPolicyCommonAccessPolicy
				err = mapstructure.Decode(*policy, &commonPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode policy page: %v", err)
					continue
				}
				policies.Items[idx] = &commonPolicy
			}
			policyPagesWithType <- &policies
		}
	}()
	return policyPagesWithType, nil
}

// ListPoliciesBy retrieves policies based on the provided filters.
func (s *IdsecPolicyService) ListPoliciesBy(filters *policycommonmodels.IdsecPolicyFilters) (<-chan *IdsecPolicyPolicyPage, error) {
	s.Logger.Info("Listing policies by filter")
	policyPagesWithType := make(chan *IdsecPolicyPolicyPage)
	go func() {
		if filters == nil {
			filters = policycommonmodels.NewIdsecPolicyFilters()
		}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			s.Logger.Error("Failed to list policies by filter: %v", err)
			close(policyPagesWithType)
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			policies := IdsecPolicyPolicyPage{Items: make([]*policycommonmodels.IdsecPolicyCommonAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var commonPolicy policycommonmodels.IdsecPolicyCommonAccessPolicy
				err = mapstructure.Decode(*policy, &commonPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode policy page: %v", err)
					continue
				}
				policies.Items[idx] = &commonPolicy
			}
			policyPagesWithType <- &policies
		}
	}()
	return policyPagesWithType, nil
}

// PolicyStatus retrieves the status of a policy by its ID or name.
func (s *IdsecPolicyService) PolicyStatus(getPolicyStatus *policycommonmodels.IdsecPolicyGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(policycommonmodels.IdsecPolicyCommonAccessPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats retrieves statistics for all policies.
func (s *IdsecPolicyService) PoliciesStats() (*policycommonmodels.IdsecPolicyStatistics, error) {
	s.Logger.Info("Retrieving policies statistics")
	filters := policycommonmodels.NewIdsecPolicyFilters()
	stats, err := s.baseService.BasePoliciesStats(filters)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve policies statistics: %w", err)
	}
	return stats, nil
}

// ServiceConfig returns the service configuration for IdsecPolicyService.
func (s *IdsecPolicyService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
