package models

// IdsecSIAAddTargetSet represents the request to add a target set in a workspace.
type IdsecSIAAddTargetSet struct {
	Name                        string `json:"name" mapstructure:"name" flag:"name" desc:"The name of the target set." validate:"required"`
	Description                 string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"The description of the target set."`
	ProvisionFormat             string `json:"provision_format,omitempty" mapstructure:"provision_format,omitempty" flag:"provision-format" desc:"The provisioning format of the target set."`
	EnableCertificateValidation bool   `json:"enable_certificate_validation,omitempty" mapstructure:"enable_certificate_validation,omitempty" flag:"enable-certificate-validation" desc:"Indicates whether to enable certificate validation for the target set."`
	SecretType                  string `json:"secret_type,omitempty" mapstructure:"secret_type,omitempty" flag:"secret-type" desc:"The Secret type of the target set (ProvisionerUser, PCloudAccount)." choices:"ProvisionerUser,PCloudAccount"`
	SecretID                    string `json:"secret_id,omitempty" mapstructure:"secret_id,omitempty" flag:"secret-id" desc:"The Secret ID of the target set."`
	Type                        string `json:"type" mapstructure:"type" flag:"type" desc:"The type of the target set (Domain, Suffix, Target)." default:"Domain" choices:"Domain,Suffix,Target"`
}
