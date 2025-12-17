package actions

import (
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// ActionToSchemaMap defines the mapping of action names to their schema structs for the standalone SCA service.
// Currently, the standalone service only exposes discovery capabilities.
var ActionToSchemaMap = map[string]interface{}{
	"discovery": &scamodels.IdsecSCADiscoveryRequest{},
}
