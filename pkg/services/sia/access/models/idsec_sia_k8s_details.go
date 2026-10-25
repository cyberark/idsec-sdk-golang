package models

// IdsecSIAK8SDetails represents Kubernetes-specific configuration for a k8s-ephemeral connector.
// All fields except K8SNamespace are optional; when supplied they skip the corresponding
// interactive prompt in the setup script. K8SNamespace is always required: it identifies the
// namespace used both to install the connector and, later, to uninstall it via helm.
type IdsecSIAK8SDetails struct {
	Upgrade            bool   `json:"upgrade,omitempty" mapstructure:"upgrade,omitempty" flag:"upgrade" desc:"When true, passes --upgrade to the K8s setup script to upgrade an existing installation." default:"false"`
	K8SNamespace       string `json:"k8s_namespace,omitempty" mapstructure:"k8s_namespace,omitempty" flag:"k8s-namespace" desc:"Kubernetes namespace to install the connector into. Also used to uninstall the connector later via helm." validate:"required"`
	K8SImageURI        string `json:"k8s_image_uri,omitempty" mapstructure:"k8s_image_uri,omitempty" flag:"k8s-image-uri" desc:"Full URI of the connector image (registry/repo:tag). When supplied, skips the interactive image-URI prompt."`
	K8SUsername        string `json:"k8s_username,omitempty" mapstructure:"k8s_username,omitempty" flag:"k8s-username" desc:"Service user username for the K8s connector. When supplied, skips the interactive username prompt."`
	K8SPassword        string `json:"k8s_password,omitempty" mapstructure:"k8s_password,omitempty" flag:"k8s-password" desc:"Service user password for the K8s connector. When supplied, skips the interactive password prompt." secret:"true"`
	K8SReplicas        int    `json:"k8s_replicas,omitempty" mapstructure:"k8s_replicas,omitempty" flag:"k8s-replicas" desc:"Number of connector replicas (1-10). When supplied, skips the interactive replicas prompt." validate:"omitempty,min=1,max=10"`
	K8SImagePullSecret string `json:"k8s_image_pull_secret,omitempty" mapstructure:"k8s_image_pull_secret,omitempty" flag:"k8s-image-pull-secret" desc:"Name of an existing Kubernetes pull-secret in the connector namespace. When supplied, skips the interactive prompt."`
}
