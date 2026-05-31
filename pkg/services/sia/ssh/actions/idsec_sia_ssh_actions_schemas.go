package actions

import sshmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/ssh/models"

// ActionToSchemaMap is a map that defines the mapping between SSH action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"connect": &sshmodels.IdsecSIASSHConnectExecution{},
}
