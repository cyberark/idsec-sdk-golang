// Package models provides the data structures for IDSEC Identity federation operations.
package models

// IdsecIdentityFederationFilters holds the filters for listing Federations.
type IdsecIdentityFederationFilters struct {
	FederationName string `json:"federation_name,omitempty" mapstructure:"federation_name" flag:"federation-name" desc:"Only return the federation with this display name."`
	FederationType string `json:"federation_type,omitempty" mapstructure:"federation_type" flag:"federation-type" desc:"Only return federations of this protocol." choices:"SAML 2.0,OIDC"`
}
