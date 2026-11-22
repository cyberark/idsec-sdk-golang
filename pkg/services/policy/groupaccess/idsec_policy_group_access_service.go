package groupaccess

import (
	"fmt"
	"reflect"
	"strings"

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

const accessApprovalNotSupportedMsg = "Access approval is not supported"

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

func serializeTargets(policy *groupaccessmodels.IdsecPolicyGroupAccessPolicy, policyJSON map[string]interface{}) error {
	var err error
	policyJSON["targets"], err = policy.Targets.SerializeTargets(policy.Metadata.PolicyEntitlement.LocationType)
	return err
}

// checkAccessApprovalSupported blocks dual control on Entra ID (Azure) group policies.
// The policy API stores access_approval on Entra group policies but access evaluation ignores it,
// so such a policy would look like dual control while granting access without approval. A
// non-required access_approval is dropped from the payload so Azure requests stay identical to
// policies created before dual control existed.
func checkAccessApprovalSupported(policy *groupaccessmodels.IdsecPolicyGroupAccessPolicy, policyJSON map[string]interface{}) error {
	accessApproval := policy.Conditions.AccessApproval
	if accessApproval == nil || !strings.EqualFold(policy.Metadata.PolicyEntitlement.LocationType, commonmodels.WorkspaceTypeAzure) {
		return nil
	}
	if accessApproval.Required {
		return fmt.Errorf("dual control (access_approval.required=true) is not supported for Entra ID (Azure) group access policies; " +
			"it is supported for Google (GCP) groups only. Remove access_approval from the policy to create or update it")
	}
	if conditionsJSON, ok := policyJSON["conditions"].(map[string]interface{}); ok {
		delete(conditionsJSON, "accessApproval")
	}
	return nil
}

// omitEmptyAccessWindow drops an unset access window from the payload of a dual control policy.
// The policy API requires accessWindow to be omitted entirely when accessApproval.required is true,
// but the window is a value type and always serializes, so an unset window is removed here. A window
// the caller did set is sent unchanged and left for the backend to validate.
func omitEmptyAccessWindow(policy *groupaccessmodels.IdsecPolicyGroupAccessPolicy, policyJSON map[string]interface{}) {
	accessApproval := policy.Conditions.AccessApproval
	if accessApproval == nil || !accessApproval.Required {
		return
	}
	accessWindow := policy.Conditions.AccessWindow
	if len(accessWindow.DaysOfTheWeek) > 0 || accessWindow.FromHour != "" || accessWindow.ToHour != "" {
		return
	}
	if conditionsJSON, ok := policyJSON["conditions"].(map[string]interface{}); ok {
		delete(conditionsJSON, "accessWindow")
	}
}

// wrapAccessApprovalNotSupportedErr explains a backend rejection of dual control on a tenant where it isn't enabled.
func wrapAccessApprovalNotSupportedErr(err error, accessApproval *policycommonmodels.IdsecPolicyAccessApprovalCondition) error {
	if err == nil || accessApproval == nil || !accessApproval.Required {
		return err
	}
	if !strings.Contains(err.Error(), accessApprovalNotSupportedMsg) {
		return err
	}
	return fmt.Errorf("dual control (access_approval.required=true) is not enabled for this tenant or group type; "+
		"contact Idira support to enable it, or remove access_approval from the policy to create "+
		"it without dual control: %w", err)
}

func deserializeTargets(policy *groupaccessmodels.IdsecPolicyGroupAccessPolicy, policyJSON map[string]interface{}) error {
	targetsJSON, _ := policyJSON["targets"].(map[string]interface{})
	return policy.Targets.DeserializeTargets(targetsJSON, policy.Metadata.PolicyEntitlement.LocationType)
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
	if err = serializeTargets(createPolicy, policyJSON); err != nil {
		return nil, err
	}
	if err = checkAccessApprovalSupported(createPolicy, policyJSON); err != nil {
		return nil, err
	}
	omitEmptyAccessWindow(createPolicy, policyJSON)
	respType := reflect.TypeOf(groupaccessmodels.IdsecPolicyGroupAccessPolicy{})
	policyResp, err := s.baseService.BaseCreatePolicyAndWait(policyJSON, &respType, policyStatusActiveRetryCount, delayTimeInSeconds)
	if err != nil {
		err = wrapAccessApprovalNotSupportedErr(err, createPolicy.Conditions.AccessApproval)
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
	if err = deserializeTargets(&groupAccessPolicy, policyJSON); err != nil {
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
	if err = serializeTargets(updatePolicy, policyJSON); err != nil {
		return nil, err
	}
	if err = checkAccessApprovalSupported(updatePolicy, policyJSON); err != nil {
		return nil, err
	}
	omitEmptyAccessWindow(updatePolicy, policyJSON)
	err = s.baseService.BaseUpdatePolicy(updatePolicy.Metadata.PolicyID, policyJSON)
	if err != nil {
		return nil, wrapAccessApprovalNotSupportedErr(err, updatePolicy.Conditions.AccessApproval)
	}
	respType := reflect.TypeOf(groupaccessmodels.IdsecPolicyGroupAccessPolicy{})
	if err = s.baseService.BaseWaitPolicyActive(updatePolicy.Metadata.PolicyID, &respType, policyStatusActiveRetryCount, delayTimeInSeconds, true, 10); err != nil {
		return nil, common.NewPartialStateError(err, updatePolicy)
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
				if err = deserializeTargets(&groupAccessPolicy, *policy); err != nil {
					s.Logger.Error("Failed to deserialize group assignment policy targets: %v", err)
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
				if err = deserializeTargets(&groupAccessPolicy, *policy); err != nil {
					s.Logger.Error("Failed to deserialize group assignment policy targets: %v", err)
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
