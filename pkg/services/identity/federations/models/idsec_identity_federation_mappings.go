// Package models provides the data structures for IDSEC Identity federation operations.
package models

// IdsecIdentityFederationGroupMapping maps a group assertion from the identity provider to a
// federated group. Group names are not validated: the server creates a federated group for any
// name it has not seen before.
type IdsecIdentityFederationGroupMapping struct {
	AttributeValue string `json:"attribute_value" mapstructure:"attribute_value" flag:"attribute-value" desc:"The group value the identity provider asserts." validate:"required,regexp=^\\S(.*\\S)?$"`
	GroupName      string `json:"group_name" mapstructure:"group_name" flag:"group-name" desc:"The federated group the asserted value maps to." validate:"required,regexp=^\\S(.*\\S)?$"`
}

// IdsecIdentityFederationAttributeMapping copies an identity provider attribute onto a Cloud
// Directory user attribute.
type IdsecIdentityFederationAttributeMapping struct {
	Target string `json:"target" mapstructure:"target" flag:"target" desc:"The Cloud Directory user attribute to set." validate:"required,regexp=\\S"`
	Source string `json:"source" mapstructure:"source" flag:"source" desc:"The identity provider attribute to read." validate:"required,regexp=\\S,regexp=^[^<]*(<\\s[^<]*)*<?$"`
}
