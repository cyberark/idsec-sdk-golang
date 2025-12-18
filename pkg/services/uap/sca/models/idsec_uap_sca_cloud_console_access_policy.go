package models

import (
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
)

// IdsecUAPSCACloudConsoleAccessPolicy represents the access policy for the SCA Cloud Console.
type IdsecUAPSCACloudConsoleAccessPolicy struct {
	uapcommonmodels.IdsecUAPCommonAccessPolicy `mapstructure:",squash" validate:"required"`
	Conditions                                 IdsecUAPSCAConditions            `json:"conditions" validate:"required" mapstructure:"conditions" flag:"conditions" desc:"The allowed session length, and the access window (days and times) during which a session can be started."`
	Targets                                    IdsecUAPSCACloudConsoleTarget    `json:"targets,omitempty" validate:"required" mapstructure:"targets,omitempty" flag:"targets" desc:"The types of cloud services that you can connect to"`
	InvalidResources                           IdsecUAPSCACloudInvalidResources `json:"invalid_resources,omitempty" mapstructure:"invalid_resources,omitempty" flag:"invalid-resources" desc:"Indicates the invalid resources that lead to an Error status in the policy."`
}
