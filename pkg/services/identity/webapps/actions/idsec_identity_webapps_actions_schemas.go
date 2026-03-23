package actions

import (
	webappsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/webapps/models"
)

// ActionToSchemaMap is a map that defines the mapping between Users action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"import-webapp":                    &webappsmodels.IdsecIdentityImportWebapp{},
	"update-webapp":                    &webappsmodels.IdsecIdentityUpdateWebapp{},
	"delete-webapp":                    &webappsmodels.IdsecIdentityDeleteWebapp{},
	"webapp":                           &webappsmodels.IdsecIdentityGetWebapp{},
	"list-webapps":                     nil,
	"list-webapps-by":                  &webappsmodels.IdsecIdentityWebappsFilters{},
	"set-webapp-permissions":           &webappsmodels.IdsecIdentitySetWebappPermissions{},
	"set-webapp-permission":            &webappsmodels.IdsecIdentitySetWebappPermission{},
	"webapp-permissions":               &webappsmodels.IdsecIdentityGetWebappPermissions{},
	"webapp-permission":                &webappsmodels.IdsecIdentityGetWebappPermission{},
	"list-webapp-templates":            nil,
	"list-webapp-templates-by":         &webappsmodels.IdsecIdentityWebappsTemplatesFilters{},
	"list-webapp-custom-templates":     nil,
	"list-webapp-custom-templates-by":  &webappsmodels.IdsecIdentityWebappsCustomTemplatesFilters{},
	"list-webapp-templates-categories": nil,
	"webapp-template":                  &webappsmodels.IdsecIdentityGetWebappTemplate{},
	"webapp-custom-template":           &webappsmodels.IdsecIdentityGetWebappCustomTemplate{},
	"webapp-stats":                     nil,
}
