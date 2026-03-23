package models

// Application authentication method types
const (
	ApplicationAuthMethodHash                    = "hash"
	ApplicationAuthMethodOsUser                  = "osUser"
	ApplicationAuthMethodMachineAddress          = "machineAddress"
	ApplicationAuthMethodPath                    = "path"
	ApplicationAuthMethodCertificateSerialNumber = "certificateSerialNumber"
	ApplicationAuthMethodKubernetes              = "Kubernetes"
	ApplicationAuthMethodCertificateAttr         = "certificateattr"
)

// IdsecPCloudApplicationAuthMethodCertKeyVal represents a key-value pair for certificate attributes.
type IdsecPCloudApplicationAuthMethodCertKeyVal struct {
	Key   string `json:"key" mapstructure:"key" flag:"key" desc:"The attribute key"`
	Value string `json:"value" mapstructure:"value" flag:"value" desc:"The attribute value"`
}

// IdsecPCloudApplicationAuthMethod represents the model for a pCloud application authentication method.
type IdsecPCloudApplicationAuthMethod struct {
	AppID    string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID"`
	AuthID   string `json:"auth_id" mapstructure:"auth_id" flag:"auth-id" desc:"The authentication method ID"`
	AuthType string `json:"auth_type" mapstructure:"auth_type" flag:"auth-type" desc:"The authentication method type"`

	// Applied for Certificate serial number, ip, os user, hash, path
	AuthValue string `json:"auth_value,omitempty" mapstructure:"auth_value,omitempty" flag:"auth-value" desc:"The authentication method value"`

	// Path type extras
	IsFolder             *bool `json:"is_folder,omitempty" mapstructure:"is_folder,omitempty" flag:"is-folder" desc:"Whether the auth value is a folder"`
	AllowInternalScripts *bool `json:"allow_internal_scripts,omitempty" mapstructure:"allow_internal_scripts,omitempty" flag:"allow-internal-scripts" desc:"Whether to allow internal scripts"`

	// Hash, certificate serial number, certificate type extras
	Comment string `json:"comment,omitempty" mapstructure:"comment,omitempty" flag:"comment" desc:"A comment for the authentication method"`

	// Kubernetes type extras, only one of them should exist
	Namespace   string `json:"namespace,omitempty" mapstructure:"namespace,omitempty" flag:"namespace" desc:"The Kubernetes namespace"`
	Image       string `json:"image,omitempty" mapstructure:"image,omitempty" flag:"image" desc:"The Kubernetes image"`
	EnvVarName  string `json:"env_var_name,omitempty" mapstructure:"env_var_name,omitempty" flag:"env-var-name" desc:"The Kubernetes environment variable name"`
	EnvVarValue string `json:"env_var_value,omitempty" mapstructure:"env_var_value,omitempty" flag:"env-var-value" desc:"The Kubernetes environment variable value"`

	// Certificate type extras
	Subject              []IdsecPCloudApplicationAuthMethodCertKeyVal `json:"subject,omitempty" mapstructure:"subject,omitempty" flag:"subject" desc:"The certificate subject attributes"`
	Issuer               []IdsecPCloudApplicationAuthMethodCertKeyVal `json:"issuer,omitempty" mapstructure:"issuer,omitempty" flag:"issuer" desc:"The certificate issuer attributes"`
	SubjectAlternateName []IdsecPCloudApplicationAuthMethodCertKeyVal `json:"subject_alternate_name,omitempty" mapstructure:"subject_alternate_name,omitempty" flag:"subject-alternate-name" desc:"The certificate subject alternate name attributes"`
}
