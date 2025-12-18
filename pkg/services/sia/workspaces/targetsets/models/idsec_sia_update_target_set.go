package models

// IdsecSIAUpdateTargetSet represents the structure for updating a target set in the SIA workspace.
type IdsecSIAUpdateTargetSet struct {
	ID                          string `json:"id" mapstructure:"id" flag:"id" desc:"The target set ID." validate:"required"`
	Name                        string `json:"name,omitempty" mapstructure:"name" flag:"name" desc:"The new name of the target set to update."`
	Description                 string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"The updated description of the target set."`
	ProvisionFormat             string `json:"provision_format,omitempty" mapstructure:"provision_format,omitempty" flag:"provision-format" desc:"The new provisioning format for the target set."`
	EnableCertificateValidation bool   `json:"enable_certificate_validation,omitempty" mapstructure:"enable_certificate_validation,omitempty" flag:"enable-certificate-validation" desc:"The updated enabling certificate validation."`
	SecretType                  string `json:"secret_type,omitempty" mapstructure:"secret_type,omitempty" flag:"secret-type" desc:"The Secret type to update (ProvisionerUser, PCloudAccount)." choices:"ProvisionerUser,PCloudAccount"`
	SecretID                    string `json:"secret_id,omitempty" mapstructure:"secret_id,omitempty" flag:"secret-id" desc:"The Secret ID to update."`
	Type                        string `json:"type,omitempty" mapstructure:"type,omitempty" flag:"type" desc:"The type of the target set." choices:"Domain,Suffix,Target"`
}
