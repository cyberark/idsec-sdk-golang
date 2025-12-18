package models

// IdsecSIADeleteTargetSet represents the request to delete a target set in a workspace.
type IdsecSIADeleteTargetSet struct {
	ID string `json:"id" mapstructure:"id" flag:"id" desc:"The ID of the target set to delete." validate:"required"`
}
