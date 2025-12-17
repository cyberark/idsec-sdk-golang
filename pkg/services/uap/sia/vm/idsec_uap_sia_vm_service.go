package vm

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	uap "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common"
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsiavmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/vm/models"

	"reflect"
)

// IdsecUAPVMPolicyPage represents a page of SIA VM policies in the UAP service.
type IdsecUAPVMPolicyPage = common.IdsecPage[uapsiavmmodels.IdsecUAPSIAVMAccessPolicy]

// IdsecUAPSIAVMService represents the UAP SIA VM service.
type IdsecUAPSIAVMService struct {
	services.IdsecService
	*services.IdsecBaseService
	baseService *uap.IdsecUAPBaseService
}

// NewIdsecUAPSIAVMService creates a new instance of IdsecUAPSIAVMService with the provided authenticators.
func NewIdsecUAPSIAVMService(authenticators ...auth.IdsecAuth) (*IdsecUAPSIAVMService, error) {
	uapSiaVMService := &IdsecUAPSIAVMService{}
	var uapSiaVMServiceInterface services.IdsecService = uapSiaVMService
	baseService, err := services.NewIdsecBaseService(uapSiaVMServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	uapSiaVMService.IdsecBaseService = baseService
	uapSiaVMService.baseService, err = uap.NewIdsecUAPBaseService(
		ispAuth,
	)
	if err != nil {
		return nil, err
	}
	return uapSiaVMService, nil
}

// AddPolicy adds a new policy with the given information.
func (s *IdsecUAPSIAVMService) AddPolicy(addPolicy *uapsiavmmodels.IdsecUAPSIAVMAccessPolicy) (*uapsiavmmodels.IdsecUAPSIAVMAccessPolicy, error) {
	s.Logger.Info("Adding new policy [%s]", addPolicy.Metadata.Name)
	addPolicy.Metadata.PolicyEntitlement.TargetCategory = commonmodels.CategoryTypeVM
	if addPolicy.Metadata.PolicyTags == nil {
		addPolicy.Metadata.PolicyTags = make([]string, 0)
	}
	policyType := reflect.TypeOf(addPolicy)
	addPolicySerialized, err := addPolicy.Serialize()
	if err != nil {
		return nil, err
	}
	addPolicyJSON := common.ConvertToCamelCase(addPolicySerialized, &policyType)
	if err != nil {
		return nil, err
	}
	policyResp, err := s.baseService.BaseAddPolicy(addPolicyJSON.(map[string]interface{}))
	if err != nil {
		return nil, err
	}
	return s.Policy(&uapcommonmodels.IdsecUAPGetPolicyRequest{
		PolicyID: policyResp.PolicyID,
	})
}

// Policy retrieves a policy by its ID.
func (s *IdsecUAPSIAVMService) Policy(policyRequest *uapcommonmodels.IdsecUAPGetPolicyRequest) (*uapsiavmmodels.IdsecUAPSIAVMAccessPolicy, error) {
	s.Logger.Info("Retrieving policy [%s]", policyRequest.PolicyID)
	respType := reflect.TypeOf(uapsiavmmodels.IdsecUAPSIAVMAccessPolicy{})
	policyJSON, err := s.baseService.BasePolicy(policyRequest.PolicyID, &respType)
	if err != nil {
		return nil, err
	}
	policyJSONSnake := common.ConvertToSnakeCase(policyJSON, &respType)
	var vmPolicy uapsiavmmodels.IdsecUAPSIAVMAccessPolicy
	err = vmPolicy.Deserialize(policyJSONSnake.(map[string]interface{}))
	if err != nil {
		return nil, err
	}
	return &vmPolicy, nil
}

// UpdatePolicy edits an existing policy with the given information.
func (s *IdsecUAPSIAVMService) UpdatePolicy(updatePolicy *uapsiavmmodels.IdsecUAPSIAVMAccessPolicy) (*uapsiavmmodels.IdsecUAPSIAVMAccessPolicy, error) {
	s.Logger.Info("Updating policy [%s]", updatePolicy.Metadata.PolicyID)
	policyType := reflect.TypeOf(uapsiavmmodels.IdsecUAPSIAVMAccessPolicy{})
	updatePolicySerialized, err := updatePolicy.Serialize()
	if err != nil {
		return nil, err
	}
	updatePolicyJSON := common.ConvertToCamelCase(updatePolicySerialized, &policyType)
	if err != nil {
		return nil, err
	}
	err = s.baseService.BaseUpdatePolicy(updatePolicy.Metadata.PolicyID, updatePolicyJSON.(map[string]interface{}))
	if err != nil {
		return nil, err
	}
	return s.Policy(&uapcommonmodels.IdsecUAPGetPolicyRequest{
		PolicyID: updatePolicy.Metadata.PolicyID,
	})
}

// ListPolicies retrieves all policies.
func (s *IdsecUAPSIAVMService) ListPolicies() (<-chan *IdsecUAPVMPolicyPage, error) {
	s.Logger.Info("Listing all policies")
	policyPagesWithType := make(chan *IdsecUAPVMPolicyPage)
	go func() {
		filters := uapcommonmodels.NewIdsecUAPFilters()
		filters.TargetCategory = []string{commonmodels.CategoryTypeVM}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			vmPolicies := IdsecUAPVMPolicyPage{Items: make([]*uapsiavmmodels.IdsecUAPSIAVMAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var vmPolicy uapsiavmmodels.IdsecUAPSIAVMAccessPolicy
				err = mapstructure.Decode(*policy, &vmPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode policy page: %v", err)
					continue
				}
				vmPolicies.Items[idx] = &vmPolicy
			}
			policyPagesWithType <- &vmPolicies
		}
	}()
	return policyPagesWithType, nil
}

// ListPoliciesBy retrieves policies based on the provided filters.
func (s *IdsecUAPSIAVMService) ListPoliciesBy(filters *uapsiavmmodels.IdsecUAPSIAVMFilters) (<-chan *IdsecUAPVMPolicyPage, error) {
	s.Logger.Info("Listing policies by filter")
	policyPagesWithType := make(chan *IdsecUAPVMPolicyPage)
	go func() {
		if filters == nil {
			filters = &uapsiavmmodels.IdsecUAPSIAVMFilters{
				IdsecUAPFilters: *uapcommonmodels.NewIdsecUAPFilters(),
			}
		}
		filters.TargetCategory = []string{commonmodels.CategoryTypeVM}
		policyPages, err := s.baseService.BaseListPolicies(&filters.IdsecUAPFilters)
		if err != nil {
			s.Logger.Error("Failed to list policies by filter: %v", err)
			close(policyPagesWithType)
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			vmPolicies := IdsecUAPVMPolicyPage{Items: make([]*uapsiavmmodels.IdsecUAPSIAVMAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var vmPolicy uapsiavmmodels.IdsecUAPSIAVMAccessPolicy
				err = mapstructure.Decode(*policy, &vmPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode policy page: %v", err)
					continue
				}
				vmPolicies.Items[idx] = &vmPolicy
			}
			policyPagesWithType <- &vmPolicies
		}
	}()
	return policyPagesWithType, nil
}

// DeletePolicy deletes a policy by its ID.
func (s *IdsecUAPSIAVMService) DeletePolicy(deletePolicy *uapcommonmodels.IdsecUAPDeletePolicyRequest) error {
	s.Logger.Info("Deleting policy [%s]", deletePolicy.PolicyID)
	return s.baseService.BaseDeletePolicy(deletePolicy.PolicyID)
}

// PolicyStatus retrieves the status of a policy by its ID or name.
func (s *IdsecUAPSIAVMService) PolicyStatus(getPolicyStatus *uapcommonmodels.IdsecUAPGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(uapsiavmmodels.IdsecUAPSIAVMAccessPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats calculates policies statistics.
func (s *IdsecUAPSIAVMService) PoliciesStats() (*uapcommonmodels.IdsecUAPPoliciesStats, error) {
	s.Logger.Info("Calculating policies statistics")
	filters := uapcommonmodels.NewIdsecUAPFilters()
	filters.TargetCategory = []string{commonmodels.CategoryTypeVM}
	return s.baseService.BasePoliciesStats(filters)
}

// ServiceConfig returns the service configuration for IdsecUAPSIAVMService.
func (s *IdsecUAPSIAVMService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
