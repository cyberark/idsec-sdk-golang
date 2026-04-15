package actions

import (
	applicationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/applications/models"
)

// ActionToSchemaMap maps action names to their corresponding schema structures.
var ActionToSchemaMap = map[string]interface{}{
	"create":               &applicationsmodels.IdsecPCloudCreateApplication{},
	"get":                  &applicationsmodels.IdsecPCloudGetApplication{},
	"delete":               &applicationsmodels.IdsecPCloudDeleteApplication{},
	"list":                 nil,
	"list-by":              &applicationsmodels.IdsecPCloudApplicationsFilter{},
	"stats":                nil,
	"create-auth-method":   &applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{},
	"get-auth-method":      &applicationsmodels.IdsecPCloudGetApplicationAuthMethod{},
	"delete-auth-method":   &applicationsmodels.IdsecPCloudDeleteApplicationAuthMethod{},
	"list-auth-methods":    &applicationsmodels.IdsecPCloudListApplicationAuthMethods{},
	"list-auth-methods-by": &applicationsmodels.IdsecPCloudApplicationAuthMethodsFilter{},
}
