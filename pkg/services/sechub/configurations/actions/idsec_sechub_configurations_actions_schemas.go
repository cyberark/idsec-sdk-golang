package actions

import sechubconfigurations "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/configurations/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub configuration action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"get":    nil,
	"update": &sechubconfigurations.IdsecSecHubUpdateConfiguration{},
}
