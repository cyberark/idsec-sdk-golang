package db

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	uap "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common"
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsiadbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db/models"

	"reflect"
)

// IdsecUAPDBPolicyPage represents a page of SIA DB policies in the UAP service.
type IdsecUAPDBPolicyPage = common.IdsecPage[uapsiadbmodels.IdsecUAPSIADBAccessPolicy]

// IdsecUAPSIADBService represents the UAP SIA DB service.
type IdsecUAPSIADBService struct {
	services.IdsecService
	*services.IdsecBaseService
	baseService *uap.IdsecUAPBaseService
}

// NewIdsecUAPSIADBService creates a new instance of IdsecUAPSIADBService with the provided authenticators.
func NewIdsecUAPSIADBService(authenticators ...auth.IdsecAuth) (*IdsecUAPSIADBService, error) {
	uapSiaDbService := &IdsecUAPSIADBService{}
	var uapSiaDbServiceInterface services.IdsecService = uapSiaDbService
	baseService, err := services.NewIdsecBaseService(uapSiaDbServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	uapSiaDbService.IdsecBaseService = baseService
	uapSiaDbService.baseService, err = uap.NewIdsecUAPBaseService(
		ispAuth,
	)
	if err != nil {
		return nil, err
	}
	return uapSiaDbService, nil
}

func (s *IdsecUAPSIADBService) serializeProfile(policy *uapsiadbmodels.IdsecUAPSIADBAccessPolicy, policyJSON map[string]interface{}) error {
	// Fill the profiles for the instances
	var err error
	for name := range policy.Targets {
		for idx := range policy.Targets[name].Instances {
			instanceJSON := policyJSON["targets"].(map[string]interface{})[name].(map[string]interface{})["instances"].([]interface{})[idx].(map[string]interface{})
			policy.Targets[name].Instances[idx].ClearProfileFromData(instanceJSON)
			instanceJSON["profile"], err = policy.Targets[name].Instances[idx].SerializeProfile()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *IdsecUAPSIADBService) deserializeProfile(policy *uapsiadbmodels.IdsecUAPSIADBAccessPolicy, policyJSON map[string]interface{}) error {
	// Fill the profiles for the instances
	var err error
	for name := range policy.Targets {
		for idx := range policy.Targets[name].Instances {
			instanceJSON := policyJSON["targets"].(map[string]interface{})[name].(map[string]interface{})["instances"].([]interface{})[idx].(map[string]interface{})
			if instanceJSON["profile"] != nil {
				err = policy.Targets[name].Instances[idx].DeserializeProfile(instanceJSON["profile"].(map[string]interface{}))
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// AddPolicy adds a new policy with the given information.
func (s *IdsecUAPSIADBService) AddPolicy(addPolicy *uapsiadbmodels.IdsecUAPSIADBAccessPolicy) (*uapsiadbmodels.IdsecUAPSIADBAccessPolicy, error) {
	s.Logger.Info("Adding new policy [%s]", addPolicy.Metadata.Name)
	addPolicy.Metadata.PolicyEntitlement.TargetCategory = commonmodels.CategoryTypeDB
	if addPolicy.Metadata.PolicyTags == nil {
		addPolicy.Metadata.PolicyTags = make([]string, 0)
	}
	policyType := reflect.TypeOf(addPolicy)
	policyJSON, err := common.SerializeJSONCamelSchema(addPolicy, &policyType)
	if err != nil {
		return nil, err
	}
	err = s.serializeProfile(addPolicy, policyJSON)
	if err != nil {
		return nil, err
	}
	policyResp, err := s.baseService.BaseAddPolicy(policyJSON)
	if err != nil {
		return nil, err
	}
	return s.Policy(&uapcommonmodels.IdsecUAPGetPolicyRequest{
		PolicyID: policyResp.PolicyID,
	})
}

// Policy retrieves a policy by its ID.
func (s *IdsecUAPSIADBService) Policy(policyRequest *uapcommonmodels.IdsecUAPGetPolicyRequest) (*uapsiadbmodels.IdsecUAPSIADBAccessPolicy, error) {
	s.Logger.Info("Retrieving policy [%s]", policyRequest.PolicyID)
	respType := reflect.TypeOf(uapsiadbmodels.IdsecUAPSIADBAccessPolicy{})
	policyJSON, err := s.baseService.BasePolicy(policyRequest.PolicyID, &respType)
	if err != nil {
		return nil, err
	}
	var dbPolicy uapsiadbmodels.IdsecUAPSIADBAccessPolicy
	err = mapstructure.Decode(policyJSON, &dbPolicy)
	if err != nil {
		return nil, err
	}
	err = s.deserializeProfile(&dbPolicy, policyJSON)
	if err != nil {
		return nil, err
	}
	return &dbPolicy, nil
}

// UpdatePolicy edits an existing policy with the given information.
func (s *IdsecUAPSIADBService) UpdatePolicy(updatePolicy *uapsiadbmodels.IdsecUAPSIADBAccessPolicy) (*uapsiadbmodels.IdsecUAPSIADBAccessPolicy, error) {
	s.Logger.Info("Updating policy [%s]", updatePolicy.Metadata.PolicyID)
	policyType := reflect.TypeOf(uapsiadbmodels.IdsecUAPSIADBAccessPolicy{})
	policyJSON, err := common.SerializeJSONCamelSchema(updatePolicy, &policyType)
	if err != nil {
		return nil, err
	}
	err = s.serializeProfile(updatePolicy, policyJSON)
	if err != nil {
		return nil, err
	}
	err = s.baseService.BaseUpdatePolicy(updatePolicy.Metadata.PolicyID, policyJSON)
	if err != nil {
		return nil, err
	}
	return s.Policy(&uapcommonmodels.IdsecUAPGetPolicyRequest{
		PolicyID: updatePolicy.Metadata.PolicyID,
	})
}

// ListPolicies retrieves all policies.
func (s *IdsecUAPSIADBService) ListPolicies() (<-chan *IdsecUAPDBPolicyPage, error) {
	s.Logger.Info("Listing all policies")
	policyPagesWithType := make(chan *IdsecUAPDBPolicyPage)
	go func() {
		filters := uapcommonmodels.NewIdsecUAPFilters()
		filters.TargetCategory = []string{commonmodels.CategoryTypeDB}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			dbPolicies := IdsecUAPDBPolicyPage{Items: make([]*uapsiadbmodels.IdsecUAPSIADBAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var dbPolicy uapsiadbmodels.IdsecUAPSIADBAccessPolicy
				err = mapstructure.Decode(*policy, &dbPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode policy page: %v", err)
					continue
				}
				dbPolicies.Items[idx] = &dbPolicy
			}
			policyPagesWithType <- &dbPolicies
		}
	}()
	return policyPagesWithType, nil
}

// ListPoliciesBy retrieves policies based on the provided filters.
func (s *IdsecUAPSIADBService) ListPoliciesBy(filters *uapsiadbmodels.IdsecUAPSIADBFilters) (<-chan *IdsecUAPDBPolicyPage, error) {
	s.Logger.Info("Listing policies by filter")
	policyPagesWithType := make(chan *IdsecUAPDBPolicyPage)
	go func() {
		if filters == nil {
			filters = &uapsiadbmodels.IdsecUAPSIADBFilters{
				IdsecUAPFilters: *uapcommonmodels.NewIdsecUAPFilters(),
			}
		}
		filters.TargetCategory = []string{commonmodels.CategoryTypeDB}
		policyPages, err := s.baseService.BaseListPolicies(&filters.IdsecUAPFilters)
		if err != nil {
			s.Logger.Error("Failed to list policies by filter: %v", err)
			close(policyPagesWithType)
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			dbPolicies := IdsecUAPDBPolicyPage{Items: make([]*uapsiadbmodels.IdsecUAPSIADBAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var dbPolicy uapsiadbmodels.IdsecUAPSIADBAccessPolicy
				err = mapstructure.Decode(*policy, &dbPolicy)
				if err != nil {
					s.Logger.Error("Failed to decode policy page: %v", err)
					continue
				}
				dbPolicies.Items[idx] = &dbPolicy
			}
			policyPagesWithType <- &dbPolicies
		}
	}()
	return policyPagesWithType, nil
}

// DeletePolicy deletes a policy by its ID.
func (s *IdsecUAPSIADBService) DeletePolicy(deletePolicy *uapcommonmodels.IdsecUAPDeletePolicyRequest) error {
	s.Logger.Info("Deleting policy [%s]", deletePolicy.PolicyID)
	return s.baseService.BaseDeletePolicy(deletePolicy.PolicyID)
}

// PolicyStatus retrieves the status of a policy by its ID or name.
func (s *IdsecUAPSIADBService) PolicyStatus(getPolicyStatus *uapcommonmodels.IdsecUAPGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(uapsiadbmodels.IdsecUAPSIADBAccessPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats calculates policies statistics.
func (s *IdsecUAPSIADBService) PoliciesStats() (*uapcommonmodels.IdsecUAPPoliciesStats, error) {
	s.Logger.Info("Calculating policies statistics")
	filters := uapcommonmodels.NewIdsecUAPFilters()
	filters.TargetCategory = []string{commonmodels.CategoryTypeDB}
	return s.baseService.BasePoliciesStats(filters)
}

// ServiceConfig returns the service configuration for IdsecUAPSIADBService.
func (s *IdsecUAPSIADBService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
