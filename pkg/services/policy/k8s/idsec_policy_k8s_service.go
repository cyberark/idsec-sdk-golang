package k8s

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
	policyk8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/k8s/models"
)

const (
	policyStatusActiveRetryCount = 100
	delayTimeInSeconds           = 3
)

// IdsecPolicyK8sPolicyPage represents a page of K8s cluster access policies.
type IdsecPolicyK8sPolicyPage = common.IdsecPage[policyk8smodels.IdsecPolicyK8sPolicy]

// IdsecPolicyK8sService exposes K8s cluster policy operations over the shared Policy base service.
type IdsecPolicyK8sService struct {
	*services.IdsecBaseService
	baseService *policycommon.IdsecPolicyBaseService
}

// NewIdsecPolicyK8sService creates a new instance of IdsecPolicyK8sService.
func NewIdsecPolicyK8sService(authenticators ...auth.IdsecAuth) (*IdsecPolicyK8sService, error) {
	k8sPolicyService := &IdsecPolicyK8sService{}
	var serviceInterface services.IdsecService = k8sPolicyService
	baseService, err := services.NewIdsecBaseService(serviceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	k8sPolicyService.IdsecBaseService = baseService
	k8sPolicyService.baseService, err = policycommon.NewIdsecPolicyBaseService(ispAuth)
	if err != nil {
		return nil, err
	}
	return k8sPolicyService, nil
}

func (s *IdsecPolicyK8sService) serializeTargets(policy *policyk8smodels.IdsecPolicyK8sPolicy, policyJSON map[string]interface{}) error {
	var err error
	policy.Targets.ClearTargetsFromData(policyJSON["targets"].(map[string]interface{}))
	policyJSON["targets"], err = policy.Targets.SerializeTargets()
	return err
}

func (s *IdsecPolicyK8sService) deserializeTargets(policy *policyk8smodels.IdsecPolicyK8sPolicy, policyJSON map[string]interface{}) error {
	return policy.Targets.DeserializeTargets(policyJSON["targets"].(map[string]interface{}))
}

// CreatePolicy creates a new K8s cluster policy.
func (s *IdsecPolicyK8sService) CreatePolicy(createPolicy *policyk8smodels.IdsecPolicyK8sPolicy) (*policyk8smodels.IdsecPolicyK8sPolicy, error) {
	s.Logger.Info("Creating new k8s policy [%s]", createPolicy.Metadata.Name)
	// K8s policies are categorized separately from Cloud Console policies.
	createPolicy.Metadata.PolicyEntitlement.TargetCategory = commonmodels.CategoryTypeClusters
	if createPolicy.Metadata.PolicyTags == nil {
		createPolicy.Metadata.PolicyTags = make([]string, 0)
	}
	policyJSON, err := common.SerializeJSONCamel(createPolicy)
	if err != nil {
		return nil, err
	}
	// Serialize targets the same way CloudAccess does: strip typed keys from the camel JSON map,
	// then replace with the flattened "targets" array expected by the policy API.
	if err = s.serializeTargets(createPolicy, policyJSON); err != nil {
		return nil, err
	}
	respType := reflect.TypeOf(policyk8smodels.IdsecPolicyK8sPolicy{})
	policyResp, err := s.baseService.BaseCreatePolicyAndWait(policyJSON, &respType, policyStatusActiveRetryCount, delayTimeInSeconds)
	if err != nil {
		if policyResp != nil && policyResp.PolicyID != "" {
			s.Logger.Warning("Policy [%s] failed activation, fetching full policy for state persistence", policyResp.PolicyID)
			if partialPolicy, fetchErr := s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{PolicyID: policyResp.PolicyID}); fetchErr == nil {
				return nil, common.NewPartialStateError(err, partialPolicy)
			}
		}
		return nil, err
	}
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: policyResp.PolicyID,
	})
}

// Policy retrieves a K8s cluster policy by ID.
func (s *IdsecPolicyK8sService) Policy(policyRequest *policycommonmodels.IdsecPolicyGetPolicyRequest) (*policyk8smodels.IdsecPolicyK8sPolicy, error) {
	s.Logger.Info("Retrieving k8s policy [%s]", policyRequest.PolicyID)
	respType := reflect.TypeOf(policyk8smodels.IdsecPolicyK8sPolicy{})
	policyJSON, err := s.baseService.BasePolicy(policyRequest.PolicyID, &respType)
	if err != nil {
		return nil, err
	}
	var k8sPolicy policyk8smodels.IdsecPolicyK8sPolicy
	if err = mapstructure.Decode(policyJSON, &k8sPolicy); err != nil {
		return nil, err
	}
	// Targets are not fully reconstructed by mapstructure alone; deserialize from the raw targets map.
	if err = s.deserializeTargets(&k8sPolicy, policyJSON); err != nil {
		return nil, err
	}
	return &k8sPolicy, nil
}

// UpdatePolicy edits an existing K8s cluster policy.
func (s *IdsecPolicyK8sService) UpdatePolicy(updatePolicy *policyk8smodels.IdsecPolicyK8sPolicy) (*policyk8smodels.IdsecPolicyK8sPolicy, error) {
	s.Logger.Info("Updating k8s policy [%s]", updatePolicy.Metadata.PolicyID)
	// The policy id is the resource key used to build the update URL (/api/policies/{id}). If it is
	// missing (e.g. it was stripped from the request model before reaching the SDK), fall back to
	// resolving it by the policy name so the update targets a concrete policy instead of the
	// collection root. Set it back on the model so both the URL and the serialized body carry it.
	if updatePolicy.Metadata.PolicyID == "" {
		resolvedID, err := s.resolvePolicyIDByName(updatePolicy.Metadata.Name)
		if err != nil {
			return nil, err
		}
		updatePolicy.Metadata.PolicyID = resolvedID
		s.Logger.Info("Resolved policy id [%s] by name [%s] for update", resolvedID, updatePolicy.Metadata.Name)
	}
	policyJSON, err := common.SerializeJSONCamel(updatePolicy)
	if err != nil {
		return nil, err
	}
	if err = s.serializeTargets(updatePolicy, policyJSON); err != nil {
		return nil, err
	}
	if err = s.baseService.BaseUpdatePolicy(updatePolicy.Metadata.PolicyID, policyJSON); err != nil {
		return nil, err
	}
	respType := reflect.TypeOf(policyk8smodels.IdsecPolicyK8sPolicy{})
	if err = s.baseService.BaseWaitPolicyActive(updatePolicy.Metadata.PolicyID, &respType, policyStatusActiveRetryCount, delayTimeInSeconds, true, 10); err != nil {
		return nil, common.NewPartialStateError(err, updatePolicy)
	}
	return s.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: updatePolicy.Metadata.PolicyID,
	})
}

// resolvePolicyIDByName looks up an existing policy by its name and returns its policy id. It is used
// as a fallback for update operations that arrive without a policy id. An error is returned if the
// name is empty, the policy cannot be found, or it has no usable policy id.
func (s *IdsecPolicyK8sService) resolvePolicyIDByName(policyName string) (string, error) {
	if policyName == "" {
		return "", fmt.Errorf("cannot resolve policy id for update: both policy id and name are empty")
	}
	policyJSON, err := s.baseService.BasePolicyByName(policyName)
	if err != nil {
		return "", fmt.Errorf("cannot resolve policy id for update by name [%s]: %w", policyName, err)
	}
	metadataJSON, ok := policyJSON["metadata"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("cannot resolve policy id for update: policy [%s] has no metadata", policyName)
	}
	var metadata policycommonmodels.IdsecPolicyMetadata
	if err = mapstructure.Decode(metadataJSON, &metadata); err != nil {
		return "", fmt.Errorf("cannot resolve policy id for update: failed to decode metadata for [%s]: %w", policyName, err)
	}
	if metadata.PolicyID == "" {
		return "", fmt.Errorf("cannot resolve policy id for update: policy [%s] has an empty policy id", policyName)
	}
	return metadata.PolicyID, nil
}

// ListPolicies retrieves all K8s cluster policies.
func (s *IdsecPolicyK8sService) ListPolicies() (<-chan *IdsecPolicyK8sPolicyPage, error) {
	s.Logger.Info("Listing all k8s policies")
	policyPagesWithType := make(chan *IdsecPolicyK8sPolicyPage)
	go func() {
		defer close(policyPagesWithType)
		filters := policycommonmodels.NewIdsecPolicyFilters()
		filters.TargetCategory = []string{commonmodels.CategoryTypeClusters}
		policyPages, err := s.baseService.BaseListPolicies(filters)
		if err != nil {
			s.Logger.Error("Failed to list k8s policies: %v", err)
			return
		}
		for page := range policyPages {
			policyPagesWithType <- s.decodePolicyPage(page)
		}
	}()
	return policyPagesWithType, nil
}

// ListPoliciesBy retrieves K8s cluster policies based on the provided filters.
func (s *IdsecPolicyK8sService) ListPoliciesBy(filters *policyk8smodels.IdsecPolicyK8sFilters) (<-chan *IdsecPolicyK8sPolicyPage, error) {
	s.Logger.Info("Listing k8s policies by filter")
	policyPagesWithType := make(chan *IdsecPolicyK8sPolicyPage)
	go func() {
		defer close(policyPagesWithType)
		if filters == nil {
			filters = &policyk8smodels.IdsecPolicyK8sFilters{
				IdsecPolicyFilters: *policycommonmodels.NewIdsecPolicyFilters(),
			}
		}
		filters.TargetCategory = []string{commonmodels.CategoryTypeClusters}
		policyPages, err := s.baseService.BaseListPolicies(&filters.IdsecPolicyFilters)
		if err != nil {
			s.Logger.Error("Failed to list k8s policies by filter: %v", err)
			return
		}
		for page := range policyPages {
			policyPagesWithType <- s.decodePolicyPage(page)
		}
	}()
	return policyPagesWithType, nil
}

// TfListPoliciesBy is a Terraform-specific wrapper that drains the ListPoliciesBy channel into a
// flat list of policies.
// ⚠️  DEPRECATED: This function is deprecated and should not be used outside the Terraform provider.
func (s *IdsecPolicyK8sService) TfListPoliciesBy(filters *policyk8smodels.IdsecPolicyK8sFilters) (*policyk8smodels.IdsecPolicyK8sPolicyList, error) {
	s.Logger.Info("Listing k8s policies by filter for Terraform")
	policyPages, err := s.ListPoliciesBy(filters)
	if err != nil {
		return nil, err
	}
	result := &policyk8smodels.IdsecPolicyK8sPolicyList{Policies: []policyk8smodels.IdsecPolicyK8sPolicy{}}
	for page := range policyPages {
		if page == nil {
			continue
		}
		for _, policy := range page.Items {
			if policy != nil {
				result.Policies = append(result.Policies, *policy)
			}
		}
	}
	return result, nil
}

// TfPolicyStatus is a Terraform-specific wrapper that returns the policy status as a flat struct.
// ⚠️  DEPRECATED: This function is deprecated and should not be used outside the Terraform provider.
func (s *IdsecPolicyK8sService) TfPolicyStatus(getPolicyStatus *policycommonmodels.IdsecPolicyGetPolicyStatus) (*policyk8smodels.IdsecPolicyK8sPolicyStatus, error) {
	status, err := s.PolicyStatus(getPolicyStatus)
	if err != nil {
		return nil, err
	}
	return &policyk8smodels.IdsecPolicyK8sPolicyStatus{Status: status}, nil
}

// decodePolicyPage converts a raw policy page into a typed K8s policy page, reconstructing targets.
func (s *IdsecPolicyK8sService) decodePolicyPage(page *policycommon.IdsecPolicyBasePolicyPage) *IdsecPolicyK8sPolicyPage {
	k8sPolicies := IdsecPolicyK8sPolicyPage{Items: make([]*policyk8smodels.IdsecPolicyK8sPolicy, len(page.Items))}
	for idx, policy := range page.Items {
		var k8sPolicy policyk8smodels.IdsecPolicyK8sPolicy
		if err := mapstructure.Decode(*policy, &k8sPolicy); err != nil {
			s.Logger.Error("Failed to decode k8s policy page: %v", err)
			continue
		}
		// Targets are not fully reconstructed by mapstructure alone; deserialize from the raw targets map.
		if targets, ok := (*policy)["targets"].(map[string]interface{}); ok {
			if err := k8sPolicy.Targets.DeserializeTargets(targets); err != nil {
				s.Logger.Error("Failed to deserialize k8s policy targets: %v", err)
			}
		}
		k8sPolicies.Items[idx] = &k8sPolicy
	}
	return &k8sPolicies
}

// DeletePolicy deletes a K8s cluster policy.
func (s *IdsecPolicyK8sService) DeletePolicy(deletePolicy *policycommonmodels.IdsecPolicyDeletePolicyRequest) error {
	s.Logger.Info("Deleting k8s policy [%s]", deletePolicy.PolicyID)
	return s.baseService.BaseDeletePolicy(deletePolicy.PolicyID)
}

// PolicyStatus retrieves the status of a K8s cluster policy by its ID or name.
func (s *IdsecPolicyK8sService) PolicyStatus(getPolicyStatus *policycommonmodels.IdsecPolicyGetPolicyStatus) (string, error) {
	if getPolicyStatus == nil {
		return "", fmt.Errorf("getPolicyStatus cannot be nil")
	}
	if getPolicyStatus.PolicyID == "" && getPolicyStatus.PolicyName == "" {
		return "", fmt.Errorf("either PolicyID or PolicyName must be provided to retrieve policy status")
	}
	s.Logger.Info("Retrieving k8s policy status for ID [%s] and name [%s]", getPolicyStatus.PolicyID, getPolicyStatus.PolicyName)
	respType := reflect.TypeOf(policyk8smodels.IdsecPolicyK8sPolicy{})
	return s.baseService.BasePolicyStatus(getPolicyStatus.PolicyID, getPolicyStatus.PolicyName, &respType)
}

// PoliciesStats calculates K8s cluster policies statistics.
func (s *IdsecPolicyK8sService) PoliciesStats() (*policycommonmodels.IdsecPolicyStatistics, error) {
	s.Logger.Info("Calculating k8s policies statistics")
	filters := policycommonmodels.NewIdsecPolicyFilters()
	filters.TargetCategory = []string{commonmodels.CategoryTypeClusters}
	return s.baseService.BasePoliciesStats(filters)
}

// ServiceConfig returns the service configuration.
func (s *IdsecPolicyK8sService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

// AddExtraContextField adds a custom context field to telemetry data.
func (s *IdsecPolicyK8sService) AddExtraContextField(name, shortName, value string) error {
	return s.baseService.AddExtraContextField(name, shortName, value)
}

// ClearExtraContext removes all extra context fields from telemetry data.
func (s *IdsecPolicyK8sService) ClearExtraContext() error {
	return s.baseService.ClearExtraContext()
}
