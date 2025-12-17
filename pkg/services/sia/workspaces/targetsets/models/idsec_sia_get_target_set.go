package models

// IdsecSIAGetTargetSet represents the request to retrieve a target set in a workspace.
type IdsecSIAGetTargetSet struct {
	ID string `json:"id" mapstructure:"id" flag:"id" desc:"ID of the target set to retrieve"`
}
