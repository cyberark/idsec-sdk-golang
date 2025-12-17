package actions

import smmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/models"

// ActionToSchemaMap is a map that defines the mapping between SM action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"list-sessions":               nil,
	"count-sessions":              nil,
	"list-sessions-by":            &smmodels.IdsecSMSessionsFilter{},
	"count-sessions-by":           &smmodels.IdsecSMSessionsFilter{},
	"session":                     &smmodels.IdsecSIASMGetSession{},
	"list-session-activities":     &smmodels.IdsecSIASMGetSessionActivities{},
	"count-session-activities":    &smmodels.IdsecSIASMGetSessionActivities{},
	"list-session-activities-by":  &smmodels.IdsecSMSessionActivitiesFilter{},
	"count-session-activities-by": &smmodels.IdsecSMSessionActivitiesFilter{},
	"sessions-stats":              nil,
}
