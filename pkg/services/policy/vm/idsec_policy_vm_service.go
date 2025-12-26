package vm

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
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm/models"
)

// IdsecPolicyVMPolicyPage represents a page of Infrastructure VM policies in the Policies service.
type IdsecPolicyVMPolicyPage = common.IdsecPage[models.IdsecPolicyVMAccessPolicy]

// IdsecPolicyVMService represents the Infrastructure VM service.
type IdsecPolicyVMService struct {
	services.IdsecService
	*services.IdsecBaseService
	baseService *policycommon.IdsecPolicyBaseService
}

// NewIdsecPolicyVMService creates a new instance of IdsecPolicyVMService with the provided authenticators.
func NewIdsecPolicyVMService(authenticators ...auth.IdsecAuth) (*IdsecPolicyVMService, error) {
	policyVMService := &IdsecPolicyVMService{}
	var policyVMServiceInterface services.IdsecService = policyVMService
	baseService, err := services.NewIdsecBaseService(policyVMServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	policyVMService.IdsecBaseService = baseService
	policyVMService.baseService, err = policycommon.NewIdsecPolicyBaseService(
		ispAuth,
	)
	if err != nil {
		return nil, err
	}
	return policyVMService, nil
}

// AddPolicy adds a new policy with the given information.
func (s *IdsecPolicyVMService) AddPolicy(addPolicy *models.IdsecPolicyVMAccessPolicy) (*models.IdsecPolicyVMAccessPolicy, error) {
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
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: policyResp.PolicyID,
	})
}

// Policy retrieves a policy by its ID.
func (s *IdsecPolicyVMService) Policy(policyRequest *policycommonmodels.IdsecPolicyGetPolicyRequest) (*models.IdsecPolicyVMAccessPolicy, error) {
	s.Logger.Info("Retrieving policy [%s]", policyRequest.PolicyID)
	respType := reflect.TypeOf(models.IdsecPolicyVMAccessPolicy{})
	policyJSON, err := s.baseService.BasePolicy(policyRequest.PolicyID, &respType)
	if err != nil {
		return nil, err
	}
	policyJSONSnake := common.ConvertToSnakeCase(policyJSON, &respType)
	var vmPolicy models.IdsecPolicyVMAccessPolicy
	err = vmPolicy.Deserialize(policyJSONSnake.(map[string]interface{}))
	if err != nil {
		return nil, err
	}
	return &vmPolicy, nil
}

// UpdatePolicy edits an existing policy with the given information.
func (s *IdsecPolicyVMService) UpdatePolicy(updatePolicy *models.IdsecPolicyVMAccessPolicy) (*models.IdsecPolicyVMAccessPolicy, error) {
	s.Logger.Info("Updating policy [%s]", updatePolicy.Metadata.PolicyID)
	policyType := reflect.TypeOf(models.IdsecPolicyVMAccessPolicy{})
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
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: updatePolicy.Metadata.PolicyID,
	})
}

// ListPolicies retrieves all policies.
func (s *IdsecPolicyVMService) ListPolicies() (<-chan *IdsecPolicyVMPolicyPage, error) {
	s.Logger.Info("Listing all policies")
	policyPagesWithType := make(chan *IdsecPolicyVMPolicyPage)
	go func() {
		filters := policycommonmodels.NewIdsecPolicyFilters()
		filters.TargetCategory = []string{commonmodels.CategoryTypeVM}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			vmPolicies := IdsecPolicyVMPolicyPage{Items: make([]*models.IdsecPolicyVMAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var vmPolicy models.IdsecPolicyVMAccessPolicy
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
func (s *IdsecPolicyVMService) ListPoliciesBy(filters *models.IdsecPolicyVMFilters) (<-chan *IdsecPolicyVMPolicyPage, error) {
	s.Logger.Info("Listing policies by filter")
	policyPagesWithType := make(chan *IdsecPolicyVMPolicyPage)
	go func() {
		if filters == nil {
			filters = &models.IdsecPolicyVMFilters{
				IdsecPolicyFilters: *policycommonmodels.NewIdsecPolicyFilters(),
			}
		}
		filters.TargetCategory = []string{commonmodels.CategoryTypeVM}
		policyPages, err := s.baseService.BaseListPolicies(&filters.IdsecPolicyFilters)
		if err != nil {
			s.Logger.Error("Failed to list policies by filter: %v", err)
			close(policyPagesWithType)
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			vmPolicies := IdsecPolicyVMPolicyPage{Items: make([]*models.IdsecPolicyVMAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var vmPolicy models.IdsecPolicyVMAccessPolicy
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
func (s *IdsecPolicyVMService) DeletePolicy(deletePolicy *policycommonmodels.IdsecPolicyDeletePolicyRequest) error {
	s.Logger.Info("Deleting policy [%s]", deletePolicy.PolicyID)
	return s.baseService.BaseDeletePolicy(deletePolicy.PolicyID)
}

// PolicyStatus retrieves the status of a policy by its ID or name.
func (s *IdsecPolicyVMService) PolicyStatus(getPolicyStatus *policycommonmodels.IdsecPolicyGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(models.IdsecPolicyVMAccessPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats calculates policies statistics.
func (s *IdsecPolicyVMService) PoliciesStats() (*policycommonmodels.IdsecPolicyStatistics, error) {
	s.Logger.Info("Calculating policies statistics")
	filters := policycommonmodels.NewIdsecPolicyFilters()
	filters.TargetCategory = []string{commonmodels.CategoryTypeVM}
	return s.baseService.BasePoliciesStats(filters)
}

// ServiceConfig returns the service configuration for IdsecPolicyVMService.
func (s *IdsecPolicyVMService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
