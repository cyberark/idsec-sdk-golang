package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyDBAccessPolicy represents a DB access policy for infrastructure.
type IdsecPolicyDBAccessPolicy struct {
	policycommonmodels.IdsecPolicyInfraCommonAccessPolicy `mapstructure:",squash"`
	Targets                                               map[string]IdsecPolicyDBTargets `json:"targets,omitempty" mapstructure:"targets,omitempty" flag:"targets" desc:"The targets of the database access policy." choices:"FQDN/IP"`
}
