package actions

import workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"

// ActionToSchemaMap is a map that defines the mapping between DB workspace action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"add-database":             &workspacesdbmodels.IdsecSIADBAddDatabase{},
	"delete-database":          &workspacesdbmodels.IdsecSIADBDeleteDatabase{},
	"update-database":          &workspacesdbmodels.IdsecSIADBUpdateDatabase{},
	"database":                 &workspacesdbmodels.IdsecSIADBGetDatabase{},
	"list-databases":           nil,
	"list-databases-by":        &workspacesdbmodels.IdsecSIADBDatabasesFilter{},
	"databases-stats":          nil,
	"list-engine-types":        nil,
	"list-family-types":        nil,
	"add-database-target":      &workspacesdbmodels.IdsecSIADBAddDatabaseTarget{},
	"delete-database-target":   &workspacesdbmodels.IdsecSIADBDeleteDatabaseTarget{},
	"update-database-target":   &workspacesdbmodels.IdsecSIADBUpdateDatabaseTarget{},
	"database-target":          &workspacesdbmodels.IdsecSIADBGetDatabaseTarget{},
	"list-database-targets":    nil,
	"list-database-targets-by": &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{},
	"database-targets-stats":   nil,
}

// TargetActionToTargetSchemaMap is a map that defines the mapping between DB workspace action names and their corresponding schema types,
// using the database-onboarding new API.
var TargetActionToTargetSchemaMap = map[string]interface{}{
	"add-database-target":      &workspacesdbmodels.IdsecSIADBAddDatabaseTarget{},
	"delete-database-target":   &workspacesdbmodels.IdsecSIADBDeleteDatabaseTarget{},
	"update-database-target":   &workspacesdbmodels.IdsecSIADBUpdateDatabaseTarget{},
	"database-target":          &workspacesdbmodels.IdsecSIADBGetDatabaseTarget{},
	"list-database-targets":    nil,
	"list-database-targets-by": &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{},
	"database-targets-stats":   nil,
	"list-engine-types":        nil,
	"list-family-types":        nil,
}
