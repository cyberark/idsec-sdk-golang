package actions

import (
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/groupaccess/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// ActionToSchemaMap maps groupaccess action names to their input schema structs.
var ActionToSchemaMap = map[string]interface{}{
	"list-targets": &scamodels.IdsecSCAListTargetsRequest{},
	"elevate":      &groupaccessmodels.IdsecSCAGroupAccessElevateActionRequest{},
}
