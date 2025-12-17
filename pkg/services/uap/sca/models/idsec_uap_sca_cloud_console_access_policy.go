package models

import (
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
)

// IdsecUAPSCACloudConsoleAccessPolicy represents the access policy for the SCA Cloud Console.
type IdsecUAPSCACloudConsoleAccessPolicy struct {
	uapcommonmodels.IdsecUAPCommonAccessPolicy `mapstructure:",squash"`
	Conditions                                 IdsecUAPSCAConditions            `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The time and session conditions of the policy"`
	Targets                                    IdsecUAPSCACloudConsoleTarget    `json:"targets,omitempty" mapstructure:"targets,omitempty" flag:"targets" desc:"The targeted cloud provider and workspace"`
	InvalidResources                           IdsecUAPSCACloudInvalidResources `json:"invalid_resources,omitempty" mapstructure:"invalid_resources,omitempty" flag:"invalid-resources" desc:"Resources that are not valid for the policy"`
}
