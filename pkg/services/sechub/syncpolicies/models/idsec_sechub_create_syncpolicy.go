package models

// IdsecSechubCreateSyncPolicy represents a sync policy for the sechub service.
// It includes information about the policy name, desc, source, target, filter, and transformation.
type IdsecSechubCreateSyncPolicy struct {
	Name           string                          `json:"name" mapstructure:"name" desc:"Name of the sync policy" flag:"name" validate:"required"`
	Description    string                          `json:"description,omitempty" mapstructure:"description,omitempty" desc:"Description of the sync policy" flag:"desc,omitempty"`
	Source         IdsecSecHubPolicyStore          `json:"source" mapstructure:"source" desc:"Source store reference" flag:"source"`
	Target         IdsecSecHubPolicyStore          `json:"target" mapstructure:"target" desc:"Target store reference" flag:"target"`
	Filter         IdsecSecHubPolicyFilter         `json:"filter" mapstructure:"filter" desc:"Filter reference" flag:"filter"`
	Transformation IdsecSecHubPolicyTransformation `json:"transformation,omitzero" mapstructure:"transformation,omitempty" desc:"Transformation reference" flag:"transformation"`
}
