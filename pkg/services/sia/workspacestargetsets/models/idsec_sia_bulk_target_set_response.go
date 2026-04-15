package models

// IdsecSIABulkTargetSetItemResult represents the result of a bulk operation on a target set in a workspace.
type IdsecSIABulkTargetSetItemResult struct {
	StrongAccountID string `json:"strong_account_id,omitempty" mapstructure:"strong_account_id,omitempty" flag:"strong-account-id" desc:"The strong account related to the bulk add."`
	TargetSetName   string `json:"target_set_name" mapstructure:"target_set_name" flag:"target-set-name" desc:"The target set item name." validate:"required"`
	Success         bool   `json:"success" mapstructure:"success" flag:"success" desc:"Indicates whether the operation was successful." validate:"required"`
}

// IdsecSIABulkTargetSetResponse represents the response for a bulk operation on target sets in a workspace.
type IdsecSIABulkTargetSetResponse struct {
	Results []IdsecSIABulkTargetSetItemResult `json:"results" mapstructure:"results" flag:"results" desc:"The list of results for the target set bulk operation." validate:"required,dive"`
}
