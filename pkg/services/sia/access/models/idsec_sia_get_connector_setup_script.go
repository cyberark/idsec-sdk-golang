package models

// IdsecSIAGetConnectorSetupScript represents the setup script details for getting a connector.
type IdsecSIAGetConnectorSetupScript struct {
	ConnectorType      string `json:"connector_type,omitempty" mapstructure:"connector_type,omitempty" flag:"connector-type" desc:"The type of the platform on which to install the connector (ON-PREMISE, AWS, AZURE, GCP)." choices:"ON-PREMISE,AWS,AZURE,GCP" deprecated:""`
	ConnectorOS        string `json:"connector_os" mapstructure:"connector_os" flag:"connector-os" desc:"The type of the operating system on which to install the connector (Linux, Windows, k8s-ephemeral)." default:"linux" choices:"linux,windows,k8s-ephemeral"`
	ConnectorPoolID    string `json:"connector_pool_id,omitempty" mapstructure:"connector_pool_id,omitempty" flag:"connector-pool-id" desc:"The connector pool to assign to this connector. For default pool leave empty."`
	Upgrade            bool   `json:"upgrade,omitempty" mapstructure:"upgrade,omitempty" flag:"upgrade" desc:"When true, passes --upgrade to the K8s setup script to upgrade an existing installation." default:"false"`
	K8SUsername        string `json:"k8s_username,omitempty" mapstructure:"k8s_username,omitempty" flag:"k8s-username" desc:"Service user username for the K8s connector. When supplied, skips the interactive username prompt."`
	K8SPassword        string `json:"k8s_password,omitempty" mapstructure:"k8s_password,omitempty" flag:"k8s-password" desc:"Service user password for the K8s connector. When supplied, skips the interactive password prompt." secret:"true"`
	K8SReplicas        int    `json:"k8s_replicas,omitempty" mapstructure:"k8s_replicas,omitempty" flag:"k8s-replicas" desc:"Number of connector replicas (1-10). When supplied, skips the interactive replicas prompt." validate:"omitempty,min=1,max=10"`
	K8SNamespace       string `json:"k8s_namespace,omitempty" mapstructure:"k8s_namespace,omitempty" flag:"k8s-namespace" desc:"Kubernetes namespace to install into. When supplied, skips the interactive namespace prompt."`
	K8SImageURI        string `json:"k8s_image_uri,omitempty" mapstructure:"k8s_image_uri,omitempty" flag:"k8s-image-uri" desc:"Full URI of the connector image (registry/repo:tag). When supplied, skips the interactive image-URI prompt."`
	K8SImagePullSecret string `json:"k8s_image_pull_secret,omitempty" mapstructure:"k8s_image_pull_secret,omitempty" flag:"k8s-image-pull-secret" desc:"Name of an existing Kubernetes pull-secret in the connector namespace. When supplied, skips the interactive prompt."`
}
