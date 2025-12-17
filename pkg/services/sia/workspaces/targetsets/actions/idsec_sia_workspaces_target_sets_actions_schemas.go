package actions

import targetsetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/targetsets/models"

// ActionToSchemaMap is a map that defines the mapping between TargetSets action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"add-target-set":                &targetsetsmodels.IdsecSIAAddTargetSet{},
	"bulk-add-target-sets":          &targetsetsmodels.IdsecSIABulkAddTargetSets{},
	"delete-target-set":             &targetsetsmodels.IdsecSIADeleteTargetSet{},
	"bulk-delete-target-sets":       &targetsetsmodels.IdsecSIABulkDeleteTargetSets{},
	"update-target-set":             &targetsetsmodels.IdsecSIAUpdateTargetSet{},
	"list-target-sets":              nil,
	"list-target-sets-by":           &targetsetsmodels.IdsecSIATargetSetsFilter{},
	"list-target-sets-with-options": &targetsetsmodels.IdsecSIAListTargetSetsOptions{},
	"target-set":                    &targetsetsmodels.IdsecSIAGetTargetSet{},
	"bulk-target-sets":              &targetsetsmodels.IdsecSIAGetTargetSets{},
	"target-sets-count":             &targetsetsmodels.IdsecSIATargetSetsCountOptions{},
	"target-sets-stats":             nil,
}
