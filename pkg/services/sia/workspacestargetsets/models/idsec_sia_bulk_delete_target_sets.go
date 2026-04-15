package models

// IdsecSIABulkDeleteTargetSets represents the request to delete multiple target sets in a workspace.
type IdsecSIABulkDeleteTargetSets struct {
	TargetSets []string `json:"target_sets" mapstructure:"target_sets" flag:"target-sets" desc:"The list of target set names to delete." validate:"required,dive,required"`
}
