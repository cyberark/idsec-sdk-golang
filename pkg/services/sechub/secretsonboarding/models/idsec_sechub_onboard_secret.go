package models

// IdsecSecHubOnboardingPamAccountProperty represents a single property value in the PAM account
// for Secrets Hub onboarding. Each property is a oneOf: either a literal VALUE or a KEY_REF
// that references a key inside the external secret.
type IdsecSecHubOnboardingPamAccountProperty struct {
	Type   string `json:"type" mapstructure:"type" desc:"Property type (VALUE,KEY_REF)" choices:"VALUE,KEY_REF" validate:"required,oneof=VALUE KEY_REF"`
	Value  string `json:"value,omitempty" mapstructure:"value,omitempty" desc:"Literal value. Required when type is VALUE."`
	KeyRef string `json:"key_ref,omitempty" mapstructure:"key_ref,omitempty" desc:"Key in the secret. Required when type is KEY_REF."`
}

// IdsecSecHubOnboardingPamAccount represents the PAM account configuration passed to the
// Secrets Hub onboarding API. This is a request-time descriptor that tells SecHub which
// PAM account to provision as part of the onboarding — it is not a directly managed resource.
type IdsecSecHubOnboardingPamAccount struct {
	Name                       string                                             `json:"name" mapstructure:"name" desc:"PAM account name" validate:"required"`
	PlatformID                 string                                             `json:"platform_id" mapstructure:"platform_id" desc:"PAM platform ID" validate:"required"`
	Template                   string                                             `json:"template,omitempty" mapstructure:"template,omitempty" desc:"Template string for TEMPLATE secret value type"`
	AutomaticManagementEnabled *bool                                              `json:"automatic_management_enabled,omitempty" mapstructure:"automatic_management_enabled,omitempty" desc:"Whether CPM automatically manages this account" default:"true"`
	Properties                 map[string]IdsecSecHubOnboardingPamAccountProperty `json:"properties,omitempty" mapstructure:"properties,omitempty" desc:"Account property map" validate:"omitempty,dive"`
}

// IdsecSecHubOnboardSecret represents the request to onboard a secret from an external store
// to PAM via Secrets Hub. SourceStoreType and TargetStoreType are path parameters (json:"-")
// and are excluded from the POST body by SerializeJSONCamel; they are used only to build the URL.
type IdsecSecHubOnboardSecret struct {
	SourceStoreType string                          `json:"-" mapstructure:"source_store_type" desc:"Source store type path param" choices:"AWS_ASM,GCP_GSM,AZURE_AKV,HASHICORP_VAULT,HASHICORP_VAULT_ENT" validate:"required,oneof=AWS_ASM GCP_GSM AZURE_AKV HASHICORP_VAULT HASHICORP_VAULT_ENT"`
	TargetStoreType string                          `json:"-" mapstructure:"target_store_type" desc:"Target store type path param" choices:"PAM_PCLOUD,PAM_SELF_HOSTED" validate:"required,oneof=PAM_PCLOUD PAM_SELF_HOSTED"`
	SecretID        string                          `json:"secret_id" mapstructure:"secret_id" desc:"Secrets Hub internal secret ID" validate:"required"`
	SecretValueType string                          `json:"secret_value_type" mapstructure:"secret_value_type" desc:"Secret value type" choices:"PLAINTEXT,JSON,TEMPLATE" validate:"required,oneof=PLAINTEXT JSON TEMPLATE"`
	SafeName        string                          `json:"safe_name" mapstructure:"safe_name" desc:"The Safe name as defined in PAM" validate:"required"`
	PamAccount      IdsecSecHubOnboardingPamAccount `json:"pam_account" mapstructure:"pam_account" desc:"PAM account to onboard the secret to" validate:"required"`
}
