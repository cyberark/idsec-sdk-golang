package models

// IdsecSecHubUpdateSyncPolicy struct for consistency only as updating sync policy is not permitted via terraform
type IdsecSecHubUpdateSyncPolicy struct {
	ID             string                          `json:"id" mapstructure:"id" desc:"Unique identifier of the policy"`
	Name           string                          `json:"name,omitempty" mapstructure:"name" desc:"Name of the policy"`
	Description    string                          `json:"description,omitempty" mapstructure:"description,omitempty" desc:"Description of the policy"`
	CreatedAt      string                          `json:"created_at,omitempty" mapstructure:"created_at" desc:"Timestamp when the policy was created"`
	UpdatedAt      string                          `json:"updated_at,omitempty" mapstructure:"updated_at" desc:"Timestamp when the policy was last updated"`
	CreatedBy      string                          `json:"created_by,omitempty" mapstructure:"created_by" desc:"User who created the policy"`
	UpdatedBy      string                          `json:"updated_by,omitempty" mapstructure:"updated_by" desc:"User who last updated the policy"`
	Source         IdsecSecHubPolicyStore          `json:"source,omitzero" mapstructure:"source" desc:"Source store reference"`
	Target         IdsecSecHubPolicyStore          `json:"target,omitzero" mapstructure:"target" desc:"Target store reference"`
	Filter         IdsecSecHubPolicyFilter         `json:"filter,omitzero" mapstructure:"filter" desc:"Filter reference"`
	Transformation IdsecSecHubPolicyTransformation `json:"transformation,omitzero" mapstructure:"transformation,omitempty" desc:"Transformation reference"`
	State          IdsecSecHubPolicyState          `json:"state,omitzero" mapstructure:"state" desc:"Current state of the policy"`
	Status         IdsecSecHubPolicyStatus         `json:"status,omitzero" mapstructure:"status,omitempty" desc:"Status of the policy"`
}
