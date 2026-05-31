package models

// IdsecSecHubCreateSecretStore defines the structure for creating a secret store in the Idsec Secrets Hub.
type IdsecSecHubCreateSecretStore struct {
	Type        string                     `json:"type" mapstructure:"type" flag:"type" validate:"required" desc:"The type for the secrets (AWS_ASM, AZURE_AKV,GCP_GSM,HASHICORP_VAULT,PAM_PCLOUD,PAM_SELF_HOSTED)" choices:"AWS_ASM,AZURE_AKV,GCP_GSM,HASHICORP_VAULT,PAM_PCLOUD,PAM_SELF_HOSTED"`
	Description string                     `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"A description of the secret store."`
	Name        string                     `json:"name" mapstructure:"name" desc:"The secret store name." flag:"name" validate:"required"`
	State       string                     `json:"state,omitempty" mapstructure:"state,omitempty" flag:"state" desc:"The secret store state (ENABLED,DISABLED)" default:"ENABLED" choices:"ENABLED,DISABLED"`
	Data        IdsecSecHubSecretStoreData `json:"data" mapstructure:"data" desc:"The data of the secret store depends on the secret store type."`
}
