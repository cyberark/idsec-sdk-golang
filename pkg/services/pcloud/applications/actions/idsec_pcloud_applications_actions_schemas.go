package actions

import (
	applicationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/applications/models"
)

// ActionToSchemaMap maps action names to their corresponding schema structures.
var ActionToSchemaMap = map[string]interface{}{
	"create-application":               &applicationsmodels.IdsecPCloudCreateApplication{},
	"application":                      &applicationsmodels.IdsecPCloudGetApplication{},
	"delete-application":               &applicationsmodels.IdsecPCloudDeleteApplication{},
	"list-applications":                nil,
	"list-applications-by":             &applicationsmodels.IdsecPCloudApplicationsFilter{},
	"applications-stats":               nil,
	"create-application-auth-method":   &applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{},
	"application-auth-method":          &applicationsmodels.IdsecPCloudGetApplicationAuthMethod{},
	"delete-application-auth-method":   &applicationsmodels.IdsecPCloudDeleteApplicationAuthMethod{},
	"list-application-auth-methods":    &applicationsmodels.IdsecPCloudListApplicationAuthMethods{},
	"list-application-auth-methods-by": &applicationsmodels.IdsecPCloudApplicationAuthMethodsFilter{},
}
