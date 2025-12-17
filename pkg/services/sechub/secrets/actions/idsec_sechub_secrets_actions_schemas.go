package actions

import sechubsecrets "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secrets/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub secrets action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"secrets":         nil,
	"list-secrets-by": &sechubsecrets.IdsecSecHubSecretsFilter{},
	"secrets-stats":   nil,
}
