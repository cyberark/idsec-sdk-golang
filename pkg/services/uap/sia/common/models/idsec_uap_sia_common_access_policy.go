package models

import (
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
)

// IdsecUAPSIACommonAccessPolicy represents a common access policy for SIA.
type IdsecUAPSIACommonAccessPolicy struct {
	uapcommonmodels.IdsecUAPCommonAccessPolicy `mapstructure:",squash"`
	Conditions                                 IdsecUAPSIACommonConditions `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The time, session, and idle time conditions of the policy"`
}
