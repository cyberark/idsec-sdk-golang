package actions

import (
	cloudconsolemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudconsole/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// ActionToSchemaMap maps cloud-console action names to their input schema structs.
var ActionToSchemaMap = map[string]interface{}{
	"list-targets": &scamodels.IdsecSCAListTargetsRequest{},
	"elevate":      &cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{},
}
