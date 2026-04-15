package actions

import workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacesdb/models"

// ActionToSchemaMap is a map that defines the mapping between DB workspace action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":            &workspacesdbmodels.IdsecSIADBAddDatabase{},
	"delete":            &workspacesdbmodels.IdsecSIADBDeleteDatabase{},
	"update":            &workspacesdbmodels.IdsecSIADBUpdateDatabase{},
	"get":               &workspacesdbmodels.IdsecSIADBGetDatabase{},
	"list":              nil,
	"list-by":           &workspacesdbmodels.IdsecSIADBDatabasesFilter{},
	"stats":             nil,
	"list-engine-types": nil,
	"list-family-types": nil,
	"create-target":     &workspacesdbmodels.IdsecSIADBAddDatabaseTarget{},
	"delete-target":     &workspacesdbmodels.IdsecSIADBDeleteDatabaseTarget{},
	"update-target":     &workspacesdbmodels.IdsecSIADBUpdateDatabaseTarget{},
	"get-target":        &workspacesdbmodels.IdsecSIADBGetDatabaseTarget{},
	"list-targets":      nil,
	"list-targets-by":   &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{},
	"targets-stats":     nil,
}

// TargetActionToTargetSchemaMap is a map that defines the mapping between DB workspace action names and their corresponding schema types,
// using the database-onboarding new API.
var TargetActionToTargetSchemaMap = map[string]interface{}{
	"create-target":     &workspacesdbmodels.IdsecSIADBAddDatabaseTarget{},
	"delete-target":     &workspacesdbmodels.IdsecSIADBDeleteDatabaseTarget{},
	"update-target":     &workspacesdbmodels.IdsecSIADBUpdateDatabaseTarget{},
	"get-target":        &workspacesdbmodels.IdsecSIADBGetDatabaseTarget{},
	"list-targets":      nil,
	"list-targets-by":   &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{},
	"targets-stats":     nil,
	"list-engine-types": nil,
	"list-family-types": nil,
}
