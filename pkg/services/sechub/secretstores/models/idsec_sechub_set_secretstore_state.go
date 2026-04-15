package models

// IdsecSecHubSetSecretStoreState defines the structure for setting the state of a secret store in the Idsec Secrets Hub.
type IdsecSecHubSetSecretStoreState struct {
	ID     string `json:"id" mapstructure:"id" desc:"Secret Store id to get details for" flag:"secret-store-id" validate:"required"`
	Action string `json:"action" mapstructure:"action" flag:"action" desc:"State to set secret store to (enable,disable)" default:"enable" choices:"enable,disable"`
}
