package actions

import sessionactivitiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessionactivities/models"

// ActionToSchemaMap is a map that defines the mapping between SM session activities action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"list":     &sessionactivitiesmodels.IdsecSIASMGetSessionActivities{},
	"count":    &sessionactivitiesmodels.IdsecSIASMGetSessionActivities{},
	"list-by":  &sessionactivitiesmodels.IdsecSMSessionActivitiesFilter{},
	"count-by": &sessionactivitiesmodels.IdsecSMSessionActivitiesFilter{},
}
