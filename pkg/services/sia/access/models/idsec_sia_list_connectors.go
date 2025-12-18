package models

// IdsecSIAConnector represents the schema for a connector in Idsec SIA.
type IdsecSIAConnector struct {
	ID                  string `json:"id" min_length:"2" description:"The connector ID."`
	WorkspaceID         string `json:"workspaceId" description:"The workspace ID of the connector host. It is relevant only for the following connector_host_type: AWS (the AWS Account ID) and AZURE (the subscription ID)."`
	HostInstanceID      string `json:"hostInstanceId"  description:"The host ID. For AWS, it is the Instance ID. For Azure, it is the VM resource ID."`
	Region              string `json:"region" description:"The region where the connector host is located."`
	HostIP              string `json:"hostIp" description:"The host machine."`
	HostName            string `json:"hostName" description:"The host name."`
	HostType            string `json:"hostType" description:"The platform type of the host. Valid values: AWS, AZURE or ON-PREMISE."`
	HostNetwork         string `json:"hostNetwork" description:"The virtual network of the host. For AWS, it is the VPC. For AZURE, it is the Vnet."`
	HostSubnet          string `json:"hostSubnet" description:"The subnet of the host."`
	Version             string `json:"version"  description:"The connector version."`
	ActiveSessionsCount int    `json:"activeSessionsCount" description:"The number of active sessions currently running on the connector." ge:"0"`
	Status              string `json:"status" description:"The connector's current status."`
	OS                  string `json:"os"  description:"The operating system of the connector host."`
	ProxySettings       string `json:"proxySettings"  description:"The HTTP Proxy details, if configured."`
	IsLatestVersion     bool   `json:"isLatestVersion"  description:"Indicates whether the connector is updated with the latest version."`
}

// IdsecSIAConnectorsListResponse represents the response for listing connectors in Idsec SIA.
type IdsecSIAConnectorsListResponse struct {
	Count             int                 `json:"count" `
	Items             []IdsecSIAConnector `json:"items" `
	ContinuationToken string              `json:"continuationToken" `
}
