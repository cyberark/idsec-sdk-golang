package actions

import (
	webappsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/webapps/models"
)

// ActionToSchemaMap is a map that defines the mapping between Users action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"import":                    &webappsmodels.IdsecIdentityImportWebapp{},
	"update":                    &webappsmodels.IdsecIdentityUpdateWebapp{},
	"delete":                    &webappsmodels.IdsecIdentityDeleteWebapp{},
	"get":                       &webappsmodels.IdsecIdentityGetWebapp{},
	"list":                      nil,
	"list-by":                   &webappsmodels.IdsecIdentityWebappsFilters{},
	"set-permissions":           &webappsmodels.IdsecIdentitySetWebappPermissions{},
	"set-permission":            &webappsmodels.IdsecIdentitySetWebappPermission{},
	"get-permissions":           &webappsmodels.IdsecIdentityGetWebappPermissions{},
	"get-permission":            &webappsmodels.IdsecIdentityGetWebappPermission{},
	"list-templates":            nil,
	"list-templates-by":         &webappsmodels.IdsecIdentityWebappsTemplatesFilters{},
	"list-custom-templates":     nil,
	"list-custom-templates-by":  &webappsmodels.IdsecIdentityWebappsCustomTemplatesFilters{},
	"list-templates-categories": nil,
	"get-template":              &webappsmodels.IdsecIdentityGetWebappTemplate{},
	"get-custom-template":       &webappsmodels.IdsecIdentityGetWebappCustomTemplate{},
	"stats":                     nil,
}
