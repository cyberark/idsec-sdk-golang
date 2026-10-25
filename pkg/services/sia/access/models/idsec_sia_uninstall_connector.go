package models

// IdsecSIAUninstallConnector represents the details required to install a connector.
type IdsecSIAUninstallConnector struct {
	ConnectorOS        string              `json:"connector_os" mapstructure:"connector_os" flag:"connector-os" desc:"The type of the operating system for the connector to uninstall (Linux, Windows, k8s-ephemeral)." default:"linux" choices:"linux,windows,k8s-ephemeral"`
	ConnectorID        string              `json:"connector_id,omitempty" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID to be uninstalled. Required unless connector_os is k8s-ephemeral, where a helm release may back multiple replica connectors with no single ID." validate:"required_unless=ConnectorOS k8s-ephemeral"`
	K8SDetails         *IdsecSIAK8SDetails `json:"k8s_details,omitempty" mapstructure:"k8s_details,omitempty" flag:"k8s-details" desc:"Kubernetes configuration the connector was installed with. Required when connector_os is k8s-ephemeral; K8SDetails.K8SNamespace is used to uninstall the connector by running 'helm uninstall sia-connector --namespace <k8s_namespace>' locally. This is the same k8s_details supplied at install time, so no separate value needs to be tracked for uninstall." validate:"required_if=ConnectorOS k8s-ephemeral"`
	TargetMachine      string              `json:"target_machine,omitempty" mapstructure:"target_machine" flag:"target-machine" desc:"The target machine on which to uninstall the connector. Required unless connector_os is k8s-ephemeral." validate:"required_unless=ConnectorOS k8s-ephemeral"`
	Username           string              `json:"username,omitempty" mapstructure:"username" flag:"username" desc:"The username used to connect to the target machine. Required unless connector_os is k8s-ephemeral." validate:"required_unless=ConnectorOS k8s-ephemeral"`
	Password           string              `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password used to connect to the target machine." secret:"true"`
	PrivateKeyPath     string              `json:"private_key_path,omitempty" mapstructure:"private_key_path" flag:"private-key-path" desc:"The private key file path used to connect to the target machine via SSH."`
	PrivateKeyContents string              `json:"private_key_contents,omitempty" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"The private key contents used to connect to the target machine via SSH." secret:"true"`
	RetryCount         int                 `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry the deletion API, if it fails." default:"30"`
	RetryDelay         int                 `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
	WinRMProtocol      string              `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" desc:"The protocol used for WinRM connections (HTTP, HTTPS)." default:"https" choices:"http,https"`
	ForceDelete        bool                `json:"force_delete" mapstructure:"force_delete" flag:"force-delete" desc:"When true, forces deletion of the connector even if it is active. Not applicable when connector_os is k8s-ephemeral, since no platform-side connector record is deleted in that case." default:"false"`
}
