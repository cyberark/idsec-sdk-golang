package models

// IdsecPCloudCreateApplicationAuthMethod represents the model for creating a pCloud application authentication method.
type IdsecPCloudCreateApplicationAuthMethod struct {
	AppID    string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID" validate:"required"`
	AuthType string `json:"auth_type" mapstructure:"auth_type" flag:"auth-type" desc:"The authentication method type" validate:"required,oneof=hash osUser machineAddress path certificateSerialNumber Kubernetes certificateattr"`

	// Applied for Certificate serial number, ip, os user, hash, path
	AuthValue string `json:"auth_value,omitempty" mapstructure:"auth_value,omitempty" flag:"auth-value" desc:"The authentication method value, required unless auth_type is certificateattr" validate:"required_unless=AuthType certificateattr"`

	// Path type extras
	IsFolder             *bool `json:"is_folder,omitempty" mapstructure:"is_folder,omitempty" flag:"is-folder" desc:"Whether the auth value is a folder"`
	AllowInternalScripts *bool `json:"allow_internal_scripts,omitempty" mapstructure:"allow_internal_scripts,omitempty" flag:"allow-internal-scripts" desc:"Whether to allow internal scripts"`

	// Hash, certificate serial number, certificate type extras
	Comment *string `json:"comment,omitempty" mapstructure:"comment,omitempty" flag:"comment" desc:"A comment for the authentication method"`

	// Kubernetes type extras, all of them are required together
	Namespace   *string `json:"namespace,omitempty" mapstructure:"namespace,omitempty" flag:"namespace" desc:"The Kubernetes namespace, required when auth_type is Kubernetes" validate:"required_if=AuthType Kubernetes"`
	Image       *string `json:"image,omitempty" mapstructure:"image,omitempty" flag:"image" desc:"The Kubernetes image, required when auth_type is Kubernetes" validate:"required_if=AuthType Kubernetes"`
	EnvVarName  *string `json:"env_var_name,omitempty" mapstructure:"env_var_name,omitempty" flag:"env-var-name" desc:"The Kubernetes environment variable name, required when auth_type is Kubernetes" validate:"required_if=AuthType Kubernetes"`
	EnvVarValue *string `json:"env_var_value,omitempty" mapstructure:"env_var_value,omitempty" flag:"env-var-value" desc:"The Kubernetes environment variable value, required when auth_type is Kubernetes" validate:"required_if=AuthType Kubernetes"`

	// Certificate type extras
	Subject                []IdsecPCloudApplicationAuthMethodCertKeyVal `json:"subject,omitempty" mapstructure:"subject,omitempty" flag:"subject" desc:"The certificate subject attributes"`
	Issuer                 []IdsecPCloudApplicationAuthMethodCertKeyVal `json:"issuer,omitempty" mapstructure:"issuer,omitempty" flag:"issuer" desc:"The certificate issuer attributes"`
	SubjectAlternativeName []IdsecPCloudApplicationAuthMethodCertKeyVal `json:"subject_alternative_name,omitempty" mapstructure:"subject_alternative_name,omitempty" flag:"subject-alternative-name" desc:"The certificate subject alternative name attributes"`
}
