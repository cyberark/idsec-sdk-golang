package actions

import sechubscans "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/scans/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub scans action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"get":     nil,
	"stats":   nil,
	"trigger": &sechubscans.IdsecSecHubTriggerScans{},
}
