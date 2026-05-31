package k8s

import (
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
	createPolicy.Targets.ClearTargetsFromData(policyJSON["targets"].(map[string]interface{}))
	policyJSON["targets"], err = createPolicy.Targets.SerializeTargets()
	if err != nil {
		return nil, err
	}
	respType := reflect.TypeOf(policyk8smodels.IdsecPolicyK8sPolicy{})
	policyResp, err := s.baseService.BaseCreatePolicyAndWait(policyJSON, &respType, policyStatusActiveRetryCount, delayTimeInSeconds)
	if err != nil {
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
	if err = k8sPolicy.Targets.DeserializeTargets(policyJSON["targets"].(map[string]interface{})); err != nil {
		return nil, err
	}
	return &k8sPolicy, nil
}

// DeletePolicy deletes a K8s cluster policy.
func (s *IdsecPolicyK8sService) DeletePolicy(deletePolicy *policycommonmodels.IdsecPolicyDeletePolicyRequest) error {
	s.Logger.Info("Deleting k8s policy [%s]", deletePolicy.PolicyID)
	return s.baseService.BaseDeletePolicy(deletePolicy.PolicyID)
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
