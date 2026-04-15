package actions

import sessionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessions/models"

// ActionToSchemaMap is a map that defines the mapping between SM sessions action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"list":     nil,
	"count":    nil,
	"list-by":  &sessionsmodels.IdsecSMSessionsFilter{},
	"count-by": &sessionsmodels.IdsecSMSessionsFilter{},
	"get":      &sessionsmodels.IdsecSIASMGetSession{},
	"stats":    nil,
}
