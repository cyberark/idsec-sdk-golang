package actions

import connectorsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/connectors/models"

// ActionToSchemaMap is a map that defines the mapping between connector management action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"setup-script": &connectorsmodels.IdsecCmgrGetSetupScript{},
	"install":      &connectorsmodels.IdsecCmgrInstall{},
	"uninstall":    &connectorsmodels.IdsecCmgrUninstall{},
	"get":          &connectorsmodels.IdsecCmgrGet{},
}
