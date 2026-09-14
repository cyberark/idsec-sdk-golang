package models

// IdsecSIAGetConnectorSetupScript represents the setup script details for getting a connector.
type IdsecSIAGetConnectorSetupScript struct {
	ConnectorType   string              `json:"connector_type" mapstructure:"connector_type" flag:"connector-type" desc:"The type of the platform on which to install the connector (ON-PREMISE, AWS, AZURE, GCP)." default:"ON-PREMISE" choices:"ON-PREMISE,AWS,AZURE,GCP"`
	ConnectorOS     string              `json:"connector_os" mapstructure:"connector_os" flag:"connector-os" desc:"The type of the operating system on which to install the connector (Linux, Windows, k8s-ephemeral)." default:"linux" choices:"linux,windows,k8s-ephemeral"`
	ConnectorPoolID string              `json:"connector_pool_id" mapstructure:"connector_pool_id" flag:"connector-pool-id" desc:"The connector pool that the connector will be part of. If not provided, the connector is assigned to the default pool." validate:"required"`
	K8SDetails      *IdsecSIAK8SDetails `json:"k8s_details,omitempty" mapstructure:"k8s_details,omitempty" flag:"k8s-details" desc:"Kubernetes configuration used when connector_os is k8s-ephemeral."`
}
