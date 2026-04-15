package models

// IdsecSIADBDatabaseInfo represents the structure for a database in the SIA workspace.
type IdsecSIADBDatabaseInfo struct {
	ID                          int                        `json:"id" mapstructure:"id" flag:"id" desc:"The ID of the database target that can be referenced in operations."`
	Name                        string                     `json:"name" mapstructure:"name" flag:"name" desc:"The name of the database, often referenced in policies and other APIs."`
	EnableCertificateValidation bool                       `json:"enable_certificate_validation" mapstructure:"enable_certificate_validation" flag:"enable-certification-validation" desc:"Indicates whether to enable and enforce certificate validation."`
	Certificate                 string                     `json:"certificate,omitempty" mapstructure:"certificate,omitempty" flag:"certificate" desc:"The certificate ID related to the database."`
	Services                    []string                   `json:"services" mapstructure:"services" flag:"services" desc:"The services related to the database, most commonly used with Oracle/SQL Server."`
	SecretID                    string                     `json:"secret_id,omitempty" mapstructure:"secret_id,omitempty" flag:"secret-id" desc:"The Secret identifier stored in the secret service related to the database."`
	Platform                    string                     `json:"platform,omitempty" mapstructure:"platform,omitempty" flag:"platform" desc:"The platform where the database resides." choices:"AWS,AZURE,GCP,ON-PREMISE,ATLAS"`
	ProviderInfo                IdsecSIADBDatabaseProvider `json:"provider_info" mapstructure:"provider_info" flag:"provider-info" desc:"The provider details."`
	ConfiguredAuthMethodType    string                     `json:"configured_auth_method_type,omitempty" mapstructure:"configured_auth_method_type,omitempty" flag:"configured-auth-method-type" desc:"The target configured the auth method type." choices:"ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication,atlas_ephemeral_user"`
}

// IdsecSIADBDatabaseInfoList represents the response for listing databases, with a filter or without.
type IdsecSIADBDatabaseInfoList struct {
	Items      []IdsecSIADBDatabaseInfo `json:"items" mapstructure:"items" flag:"items" desc:"The actual databases"`
	TotalCount int                      `json:"total_count" mapstructure:"total_count" flag:"total-count" desc:"Total count of databases"`
}

// IdsecSIADBDatabaseTargetInfo represents the structure for a database in the SIA workspace by the database-onboarding new API.
type IdsecSIADBDatabaseTargetInfo struct {
	ID                          string   `json:"id" mapstructure:"id" flag:"id" desc:"The ID of the database target that can be referenced in operations."`
	Name                        string   `json:"name" mapstructure:"name" flag:"name" desc:"The name of the database, often referenced in policies and other APIs."`
	EnableCertificateValidation bool     `json:"enable_certificate_validation" mapstructure:"enable_certificate_validation" flag:"enable-certification-validation" desc:"Indicates whether to enable and enforce certificate validation."`
	Certificate                 string   `json:"certificate,omitempty" mapstructure:"certificate,omitempty" flag:"certificate" desc:"The certificate ID related to the database."`
	Services                    []string `json:"services" mapstructure:"services" flag:"services" desc:"The services related to the database, most commonly used with Oracle/SQL Server."`
	SecretID                    string   `json:"secret_id,omitempty" mapstructure:"secret_id,omitempty" flag:"secret-id" desc:"The Secret identifier stored in the secret service related to the database."`
	Platform                    string   `json:"platform,omitempty" mapstructure:"platform,omitempty" flag:"platform" desc:"The platform where the database resides." choices:"AWS,AZURE,GCP,ON-PREMISE,ATLAS"`
	ProviderEngine              string   `json:"provider_engine" mapstructure:"provider_engine" flag:"provider-engine" desc:"The engine type of the database provider."`
	Family                      string   `json:"family,omitempty" mapstructure:"family,omitempty" flag:"family" desc:"The family type of the database provider."`
	ConfiguredAuthMethodType    string   `json:"configured_auth_method_type,omitempty" mapstructure:"configured_auth_method_type,omitempty" flag:"configured-auth-method-type" desc:"The target configured auth method type" choices:"ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication,atlas_ephemeral_user"`
}

// IdsecSIADBDatabaseTargetInfoList represents the response for listing databases, with a filter or without, by the database-onboarding new API.
type IdsecSIADBDatabaseTargetInfoList struct {
	Items      []IdsecSIADBDatabaseTargetInfo `json:"items" mapstructure:"items" flag:"items" desc:"The actual databases."`
	TotalCount int                            `json:"total_count" mapstructure:"total_count" flag:"total-count" desc:"The total number of databases."`
	NextCursor string                         `json:"next_cursor" mapstructure:"next_cursor" flag:"next-cursor" desc:"The cursor for the next page of results."`
}
