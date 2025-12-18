package models

// Possible values for DelegationClassification
const (
	DelegationClassificationUnrestricted = "Unrestricted"
	DelegationClassificationRestricted   = "Restricted"
)

// IdsecUAPCommonAccessPolicy represents the access policy in UAP.
type IdsecUAPCommonAccessPolicy struct {
	Metadata                 IdsecUAPMetadata    `json:"metadata,omitempty" validate:"required" mapstructure:"metadata,omitempty" flag:"metadata" desc:"The policy metadata: ID, name, and additional information"`
	Principals               []IdsecUAPPrincipal `json:"principals,omitempty" validate:"required" mapstructure:"principals,omitempty" flag:"principals" desc:"The identity: user, group, role"`
	DelegationClassification string              `json:"delegation_classification" validate:"required" mapstructure:"delegation_classification" flag:"delegation-classification" desc:"Indicates the user rights for the policy. Default: Unrestricted" choices:"Restricted,Unrestricted" default:"Unrestricted"`
}
