package actions

import (
	cloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// ActionToSchemaMap maps cloudaccess action names to their input schema structs.
var ActionToSchemaMap = map[string]interface{}{
	"list-targets": &scamodels.IdsecSCAListTargetsRequest{},
	"elevate":      &cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{},
}
