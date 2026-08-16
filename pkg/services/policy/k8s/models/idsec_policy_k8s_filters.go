package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyK8sFilters embeds the shared policy filters for K8s cluster access policies.
type IdsecPolicyK8sFilters struct {
	policycommonmodels.IdsecPolicyFilters `mapstructure:",squash"`
}
