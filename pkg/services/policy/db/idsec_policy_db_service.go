package db

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
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db/models"
)

// IdsecPolicyDBPolicyPage represents a page of Infrastructure DB policies in the policy service.
type IdsecPolicyDBPolicyPage = common.IdsecPage[models.IdsecPolicyDBAccessPolicy]

// IdsecPolicyDBService represents the Infrastructure DB service.
type IdsecPolicyDBService struct {
	*services.IdsecBaseService
	baseService *policycommon.IdsecPolicyBaseService
}

// NewIdsecPolicyDBService creates a new instance of IdsecPolicyDBService with the provided authenticators.
func NewIdsecPolicyDBService(authenticators ...auth.IdsecAuth) (*IdsecPolicyDBService, error) {
	policyDbService := &IdsecPolicyDBService{}
	var policyDbServiceInterface services.IdsecService = policyDbService
	baseService, err := services.NewIdsecBaseService(policyDbServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	policyDbService.IdsecBaseService = baseService
	policyDbService.baseService, err = policycommon.NewIdsecPolicyBaseService(
		ispAuth,
	)
	if err != nil {
		return nil, err
	}
	return policyDbService, nil
}

func (s *IdsecPolicyDBService) serializeProfile(policy *models.IdsecPolicyDBAccessPolicy, policyJSON map[string]interface{}) error {
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

func (s *IdsecPolicyDBService) deserializeProfile(policy *models.IdsecPolicyDBAccessPolicy, policyJSON map[string]interface{}) error {
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

// CreatePolicy creates a new policy with the given information.
func (s *IdsecPolicyDBService) CreatePolicy(createPolicy *models.IdsecPolicyDBAccessPolicy) (*models.IdsecPolicyDBAccessPolicy, error) {
	s.Logger.Info("Creating new policy [%s]", createPolicy.Metadata.Name)
	createPolicy.Metadata.PolicyEntitlement.TargetCategory = commonmodels.CategoryTypeDB
	if createPolicy.Metadata.PolicyTags == nil {
		createPolicy.Metadata.PolicyTags = make([]string, 0)
	}
	policyType := reflect.TypeOf(createPolicy)
	policyJSON, err := common.SerializeJSONCamelSchema(createPolicy, &policyType)
	if err != nil {
		return nil, err
	}
	err = s.serializeProfile(createPolicy, policyJSON)
	if err != nil {
		return nil, err
	}
	policyResp, err := s.baseService.BaseCreatePolicy(policyJSON)
	if err != nil {
		return nil, err
	}
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: policyResp.PolicyID,
	})
}

// Policy retrieves a policy by its ID.
func (s *IdsecPolicyDBService) Policy(policyRequest *policycommonmodels.IdsecPolicyGetPolicyRequest) (*models.IdsecPolicyDBAccessPolicy, error) {
	s.Logger.Info("Retrieving policy [%s]", policyRequest.PolicyID)
	respType := reflect.TypeOf(models.IdsecPolicyDBAccessPolicy{})
	policyJSON, err := s.baseService.BasePolicy(policyRequest.PolicyID, &respType)
	if err != nil {
		return nil, err
	}
	var dbPolicy models.IdsecPolicyDBAccessPolicy
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
func (s *IdsecPolicyDBService) UpdatePolicy(updatePolicy *models.IdsecPolicyDBAccessPolicy) (*models.IdsecPolicyDBAccessPolicy, error) {
	s.Logger.Info("Updating policy [%s]", updatePolicy.Metadata.PolicyID)
	policyType := reflect.TypeOf(models.IdsecPolicyDBAccessPolicy{})
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
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: updatePolicy.Metadata.PolicyID,
	})
}

// ListPolicies retrieves all policies.
func (s *IdsecPolicyDBService) ListPolicies() (<-chan *IdsecPolicyDBPolicyPage, error) {
	s.Logger.Info("Listing all policies")
	policyPagesWithType := make(chan *IdsecPolicyDBPolicyPage)
	go func() {
		filters := policycommonmodels.NewIdsecPolicyFilters()
		filters.TargetCategory = []string{commonmodels.CategoryTypeDB}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			dbPolicies := IdsecPolicyDBPolicyPage{Items: make([]*models.IdsecPolicyDBAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var dbPolicy models.IdsecPolicyDBAccessPolicy
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
func (s *IdsecPolicyDBService) ListPoliciesBy(filters *models.IdsecPolicyDBFilters) (<-chan *IdsecPolicyDBPolicyPage, error) {
	s.Logger.Info("Listing policies by filter")
	policyPagesWithType := make(chan *IdsecPolicyDBPolicyPage)
	go func() {
		if filters == nil {
			filters = &models.IdsecPolicyDBFilters{
				IdsecPolicyFilters: *policycommonmodels.NewIdsecPolicyFilters(),
			}
		}
		filters.TargetCategory = []string{commonmodels.CategoryTypeDB}
		policyPages, err := s.baseService.BaseListPolicies(&filters.IdsecPolicyFilters)
		if err != nil {
			s.Logger.Error("Failed to list policies by filter: %v", err)
			close(policyPagesWithType)
			return
		}
		defer close(policyPagesWithType)
		for page := range policyPages {
			dbPolicies := IdsecPolicyDBPolicyPage{Items: make([]*models.IdsecPolicyDBAccessPolicy, len(page.Items))}
			for idx, policy := range page.Items {
				var dbPolicy models.IdsecPolicyDBAccessPolicy
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
func (s *IdsecPolicyDBService) DeletePolicy(deletePolicy *policycommonmodels.IdsecPolicyDeletePolicyRequest) error {
	s.Logger.Info("Deleting policy [%s]", deletePolicy.PolicyID)
	return s.baseService.BaseDeletePolicy(deletePolicy.PolicyID)
}

// PolicyStatus retrieves the status of a policy by its ID or name.
func (s *IdsecPolicyDBService) PolicyStatus(getPolicyStatus *policycommonmodels.IdsecPolicyGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(models.IdsecPolicyDBAccessPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats calculates policies statistics.
func (s *IdsecPolicyDBService) PoliciesStats() (*policycommonmodels.IdsecPolicyStatistics, error) {
	s.Logger.Info("Calculating policies statistics")
	filters := policycommonmodels.NewIdsecPolicyFilters()
	filters.TargetCategory = []string{commonmodels.CategoryTypeDB}
	return s.baseService.BasePoliciesStats(filters)
}

// ServiceConfig returns the service configuration for IdsecPolicyDBService.
func (s *IdsecPolicyDBService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

// AddExtraContextField adds a custom context field to telemetry data.
// Delegates to the base service which has the ISP client with telemetry support.
func (s *IdsecPolicyDBService) AddExtraContextField(name, shortName, value string) error {
	return s.baseService.AddExtraContextField(name, shortName, value)
}

// ClearExtraContext removes all extra context fields from telemetry data.
// Delegates to the base service which has the ISP client with telemetry support.
func (s *IdsecPolicyDBService) ClearExtraContext() error {
	return s.baseService.ClearExtraContext()
}
