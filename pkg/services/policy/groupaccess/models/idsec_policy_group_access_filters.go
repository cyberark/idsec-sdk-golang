package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyGroupAccessFilters embeds the shared policy filters for Entra group assignment policies.
type IdsecPolicyGroupAccessFilters struct {
	policycommonmodels.IdsecPolicyFilters `mapstructure:",squash"`
}
