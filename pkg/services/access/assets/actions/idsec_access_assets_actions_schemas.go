package actions

import assetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/access/assets/models"

// ActionToSchemaMap defines the mapping between access assets action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"list":    nil,
	"list-by": &assetsmodels.IdsecAccessAssetsListAssetsRequest{},
	"secret":  &assetsmodels.IdsecAccessAssetsSecretRequest{},
}
