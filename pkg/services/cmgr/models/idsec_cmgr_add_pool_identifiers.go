package models

// IdsecCmgrAddPoolIdentifier is a struct representing the filter for adding identifiers to a pool in the Idsec CMGR service.
type IdsecCmgrAddPoolIdentifier struct {
	Type  string `json:"type" mapstructure:"type" flag:"type" desc:"Type of the identifier to add (GENERAL_FQDN,GENERAL_HOSTNAME,AWS_ACCOUNT_ID,AWS_VPC,AWS_SUBNET,AZURE_SUBSCRIPTION,AZURE_VNET,AZURE_SUBNET,GCP_PROJECT,GCP_NETWORK,GCP_SUBNET)" choices:"GENERAL_FQDN,GENERAL_HOSTNAME,AWS_ACCOUNT_ID,AWS_VPC,AWS_SUBNET,AZURE_SUBSCRIPTION,AZURE_VNET,AZURE_SUBNET,GCP_PROJECT,GCP_NETWORK,GCP_SUBNET"`
	Value string `json:"value" mapstructure:"value" flag:"value" desc:"Value of the identifier"`
}

// IdsecCmgrAddPoolSingleIdentifier is a struct representing the filter for adding a single identifier to a pool in the Idsec CMGR service.
type IdsecCmgrAddPoolSingleIdentifier struct {
	Type   string `json:"type" mapstructure:"type" flag:"type" desc:"Type of the identifier to add (GENERAL_FQDN,GENERAL_HOSTNAME,AWS_ACCOUNT_ID,AWS_VPC,AWS_SUBNET,AZURE_SUBSCRIPTION,AZURE_VNET,AZURE_SUBNET,GCP_PROJECT,GCP_NETWORK,GCP_SUBNET)" choices:"GENERAL_FQDN,GENERAL_HOSTNAME,AWS_ACCOUNT_ID,AWS_VPC,AWS_SUBNET,AZURE_SUBSCRIPTION,AZURE_VNET,AZURE_SUBNET,GCP_PROJECT,GCP_NETWORK,GCP_SUBNET"`
	Value  string `json:"value" mapstructure:"value" flag:"value" desc:"Value of the identifier"`
	PoolID string `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"ID of the pool to add the identifier to"`
}

// IdsecCmgrAddPoolBulkIdentifier is a struct representing the filter for adding multiple identifiers to a pool in the Idsec CMGR service.
type IdsecCmgrAddPoolBulkIdentifier struct {
	PoolID      string                       `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"ID of the pool to add the identifiers to"`
	Identifiers []IdsecCmgrAddPoolIdentifier `json:"identifiers" mapstructure:"identifiers" flag:"identifiers" desc:"Identifiers to add"`
}
