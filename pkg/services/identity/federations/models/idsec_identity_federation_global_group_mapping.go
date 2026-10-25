// Package models provides the data structures for IDSEC Identity federation operations.
package models

// IdsecIdentityFederationGlobalGroupMapping is a group mapping that applies to every federation.
type IdsecIdentityFederationGlobalGroupMapping struct {
	AttributeValue string `json:"attribute_value" mapstructure:"attribute_value" flag:"attribute-value" desc:"The group value an identity provider asserts." validate:"required"`
	GroupName      string `json:"group_name" mapstructure:"group_name" flag:"group-name" desc:"The federated group the asserted value maps to." validate:"required"`
}

// IdsecIdentityAddFederationGlobalGroupMapping is the write model for adding a global group mapping.
type IdsecIdentityAddFederationGlobalGroupMapping struct {
	AttributeValue string `json:"attribute_value" mapstructure:"attribute_value" flag:"attribute-value" desc:"The group value an identity provider asserts." validate:"required"`
	GroupName      string `json:"group_name" mapstructure:"group_name" flag:"group-name" desc:"The federated group the asserted value maps to." validate:"required"`
}

// IdsecIdentityGetFederationGlobalGroupMapping identifies a global group mapping.
type IdsecIdentityGetFederationGlobalGroupMapping struct {
	AttributeValue string `json:"attribute_value" mapstructure:"attribute_value" flag:"attribute-value" desc:"The group value an identity provider asserts." validate:"required"`
	GroupName      string `json:"group_name" mapstructure:"group_name" flag:"group-name" desc:"The federated group the asserted value maps to." validate:"required"`
}

// IdsecIdentityRemoveFederationGlobalGroupMapping identifies the global group mapping to remove.
type IdsecIdentityRemoveFederationGlobalGroupMapping struct {
	AttributeValue string `json:"attribute_value" mapstructure:"attribute_value" flag:"attribute-value" desc:"The group value an identity provider asserts." validate:"required"`
	GroupName      string `json:"group_name" mapstructure:"group_name" flag:"group-name" desc:"The federated group the asserted value maps to." validate:"required"`
}
