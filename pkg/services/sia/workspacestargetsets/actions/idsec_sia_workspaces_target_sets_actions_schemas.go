package actions

import targetsetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacestargetsets/models"

// ActionToSchemaMap is a map that defines the mapping between TargetSets action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":            &targetsetsmodels.IdsecSIAAddTargetSet{},
	"bulk-create":       &targetsetsmodels.IdsecSIABulkAddTargetSets{},
	"delete":            &targetsetsmodels.IdsecSIADeleteTargetSet{},
	"bulk-delete":       &targetsetsmodels.IdsecSIABulkDeleteTargetSets{},
	"update":            &targetsetsmodels.IdsecSIAUpdateTargetSet{},
	"list":              nil,
	"list-by":           &targetsetsmodels.IdsecSIATargetSetsFilter{},
	"list-with-options": &targetsetsmodels.IdsecSIAListTargetSetsOptions{},
	"get":               &targetsetsmodels.IdsecSIAGetTargetSet{},
	"bulk-get":          &targetsetsmodels.IdsecSIAGetTargetSets{},
	"count":             &targetsetsmodels.IdsecSIATargetSetsCountOptions{},
	"stats":             nil,
}
