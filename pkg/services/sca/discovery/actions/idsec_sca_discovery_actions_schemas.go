package actions

import (
	discoverymodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/discovery/models"
)

// ActionToSchemaMap defines the mapping of action names to their schema structs for the SCA discovery service.
var ActionToSchemaMap = map[string]interface{}{
	"discovery": &discoverymodels.IdsecSCADiscoveryRequest{},
}
