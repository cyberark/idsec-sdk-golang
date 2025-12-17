package uap

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	uap "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common"
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"

	"reflect"
)

// IdsecUAPPolicyPage represents a page of common policies in the UAP service.
type IdsecUAPPolicyPage = common.IdsecPage[uapcommonmodels.IdsecUAPCommonAccessPolicy]

// IdsecUAPService represents the UAP service.
type IdsecUAPService struct {
	services.IdsecService
	*services.IdsecBaseService
	baseService *uap.IdsecUAPBaseService
}

// NewIdsecUAPService creates a new instance of IdsecUAPService with the provided authenticators.
func NewIdsecUAPService(authenticators ...auth.IdsecAuth) (*IdsecUAPService, error) {
	uapService := &IdsecUAPService{}
	var uapServiceInterface services.IdsecService = uapService
	baseService, err := services.NewIdsecBaseService(uapServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	uapService.IdsecBaseService = baseService
	uapService.baseService, err = uap.NewIdsecUAPBaseService(
		ispAuth,
	)
	if err != nil {
		return nil, err
	}
	return uapService, nil
}

// ListPolicies retrieves all policies.
func (s *IdsecUAPService) ListPolicies() (<-chan *IdsecUAPPolicyPage, error) {
	s.Logger.Info("Listing all policies")
	policyPagesWithType := make(chan *IdsecUAPPolicyPage)
	go func() {
		filters := uapcommonmodels.NewIdsecUAPFilters()
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			policies := IdsecUAPPolicyPage{Items: make([]*uapcommonmodels.IdsecUAPCommonAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var commonPolicy uapcommonmodels.IdsecUAPCommonAccessPolicy
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
func (s *IdsecUAPService) ListPoliciesBy(filters *uapcommonmodels.IdsecUAPFilters) (<-chan *IdsecUAPPolicyPage, error) {
	s.Logger.Info("Listing policies by filter")
	policyPagesWithType := make(chan *IdsecUAPPolicyPage)
	go func() {
		if filters == nil {
			filters = uapcommonmodels.NewIdsecUAPFilters()
		}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			s.Logger.Error("Failed to list policies by filter: %v", err)
			close(policyPagesWithType)
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			policies := IdsecUAPPolicyPage{Items: make([]*uapcommonmodels.IdsecUAPCommonAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var commonPolicy uapcommonmodels.IdsecUAPCommonAccessPolicy
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
func (s *IdsecUAPService) PolicyStatus(getPolicyStatus *uapcommonmodels.IdsecUAPGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(uapcommonmodels.IdsecUAPCommonAccessPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats retrieves statistics for all policies.
func (s *IdsecUAPService) PoliciesStats() (*uapcommonmodels.IdsecUAPPoliciesStats, error) {
	s.Logger.Info("Retrieving policies statistics")
	filters := uapcommonmodels.NewIdsecUAPFilters()
	stats, err := s.baseService.BasePoliciesStats(filters)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve policies statistics: %w", err)
	}
	return stats, nil
}

// ServiceConfig returns the service configuration for IdsecUAPSCAService.
func (s *IdsecUAPService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
