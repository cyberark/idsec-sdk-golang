package models

// IdsecSecHubSyncSettings represents the sync settings within the configuration settings.
type IdsecSecHubSyncSettings struct {
	SecretValidity int `json:"secret_validity" mapstructure:"secret_validity" desc:"Secret Validity period in seconds" flag:"secret-validity" validate:"required"`
}

// IdsecSecHubSecretsSource represents the secrets source within the configuration settings.
type IdsecSecHubSecretsSource struct {
	// The tenant PAM type Exxample: PCLOUD_NON_UM, PAM_SELF_HOSTED
	PAMType string `json:"pam_type" mapstructure:"pam_type" desc:"PAM Type for Secrets Source" flag:"pam-type"`
}

// IdsecSecHubAuthenticationIdentities represents the authentication identities within the configuration settings.
type IdsecSecHubAuthenticationIdentities struct {
	// Identities defines the authentication identities for the secrets hub.
	AWS IdsecSecHubAuthenticationIdentitiesAWS `json:"aws" mapstructure:"aws" desc:"AWS Authentication Identities for Secrets Hub" flag:"aws-authentication-identities"`
}

// IdsecSecHubAuthenticationIdentitiesAWS represents the AWS authentication identities within the configuration settings.
type IdsecSecHubAuthenticationIdentitiesAWS struct {
	// The Secrets Hub tenant role ARN
	TenantRoleARN string `json:"tenant_role_arn" mapstructure:"tenant_role_arn" desc:"The Secrets Hub tenant role ARN" flag:"tenant-role-arn"`
}

// IdsecSecHubGetConfiguration represents the response when requesting configuration settings.
type IdsecSecHubGetConfiguration struct {
	SyncSettings             IdsecSecHubSyncSettings             `json:"sync_settings" mapstructure:"sync_settings" desc:"Sync Settings for Secrets Hub" flag:"sync-settings"`
	SecretsSource            IdsecSecHubSecretsSource            `json:"secrets_source" mapstructure:"secrets_source" desc:"Secrets Source for Secrets Hub" flag:"secrets-source"`
	AuthenticationIdentities IdsecSecHubAuthenticationIdentities `json:"authentication_identities" mapstructure:"authentication_identities" desc:"Authentication Identities for Secrets Hub" flag:"authentication-identities"`
}
