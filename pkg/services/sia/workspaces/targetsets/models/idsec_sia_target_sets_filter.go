package models

// IdsecSIATargetSetsFilter represents the filter criteria for retrieving target sets in a workspace.
type IdsecSIATargetSetsFilter struct {
	Name       string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The name filter wildcard."`
	SecretType string `json:"secret_type,omitempty" mapstructure:"secret_type,omitempty" flag:"secret-type" desc:"The Secret type filter." choices:"ProvisionerUser,PCloudAccount"`
}
