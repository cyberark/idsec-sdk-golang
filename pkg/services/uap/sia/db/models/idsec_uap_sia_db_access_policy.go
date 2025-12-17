package models

import (
	sia "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/common/models"
)

// IdsecUAPSIADBAccessPolicy represents a DB access policy for SIA.
type IdsecUAPSIADBAccessPolicy struct {
	sia.IdsecUAPSIACommonAccessPolicy `mapstructure:",squash"`
	Targets                           map[string]IdsecUAPSIADBTargets `json:"targets,omitempty" mapstructure:"targets,omitempty" flag:"targets" desc:"The targets of the db access policy" choices:"FQDN/IP"`
}
