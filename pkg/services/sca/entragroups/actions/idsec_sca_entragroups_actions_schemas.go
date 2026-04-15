package actions

import (
	entragroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/entragroups/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// ActionToSchemaMap maps entragroups action names to their input schema structs.
var ActionToSchemaMap = map[string]interface{}{
	"list-targets": &scamodels.IdsecSCAListTargetsRequest{},
	"elevate":      &entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{},
}
