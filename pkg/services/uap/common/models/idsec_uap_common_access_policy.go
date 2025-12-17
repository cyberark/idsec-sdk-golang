package models

// Possible values for DelegationClassification
const (
	DelegationClassificationUnrestricted = "Unrestricted"
	DelegationClassificationRestricted   = "Restricted"
)

// IdsecUAPCommonAccessPolicy represents the access policy in UAP.
type IdsecUAPCommonAccessPolicy struct {
	Metadata                 IdsecUAPMetadata    `json:"metadata,omitempty" mapstructure:"metadata,omitempty" flag:"metadata" desc:"Policy metadata id name and extra information"`
	Principals               []IdsecUAPPrincipal `json:"principals,omitempty" mapstructure:"principals,omitempty" flag:"principals" desc:"List of users, groups and roles that the policy applies to"`
	DelegationClassification string              `json:"delegation_classification" mapstructure:"delegation_classification" flag:"delegation-classification" desc:"Indicates the user rights for the current policy" choices:"Restricted,Unrestricted" default:"Unrestricted"`
}
