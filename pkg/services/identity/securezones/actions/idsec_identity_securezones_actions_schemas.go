// Package actions defines the ActionToSchemaMap for the identity-securezones service,
// mapping CLI action names to their corresponding request schema structs.
package actions

import (
	securezonesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/securezones/models"
)

// ActionToSchemaMap defines the mapping between SecureZone action names and their
// corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &securezonesmodels.IdsecIdentityCreateSecureZone{},
	"update":  &securezonesmodels.IdsecIdentityUpdateSecureZone{},
	"delete":  &securezonesmodels.IdsecIdentityDeleteSecureZone{},
	"get":     &securezonesmodels.IdsecIdentityGetSecureZone{},
	"list":    nil,
	"list-by": &securezonesmodels.IdsecIdentitySecureZoneFilters{},
}
