package models

// IdsecSIAConnector represents the schema for a connector in Idsec SIA.
type IdsecSIAConnector struct {
	ID                  string `json:"id" min_length:"2" description:"The connector Id"`
	WorkspaceID         string `json:"workspaceId" description:"The workspace ID where the connector host is in, relevant only for the following connector_host_type: AWS (the AWS Account ID) and AZURE (the subscription ID)."`
	HostInstanceID      string `json:"hostInstanceId"  description:"The host ID. For AWS this is the Instance ID, for Azure this is the VM resource ID"`
	Region              string `json:"region" description:"The region where the connector host is in."`
	HostIP              string `json:"hostIp" description:"The host machine."`
	HostName            string `json:"hostName" description:"The host name."`
	HostType            string `json:"hostType" description:"The platform type where the host is in. Valid values: AWS, AZURE or ON-PREMISE."`
	HostNetwork         string `json:"hostNetwork" description:"The virtual network where the host is in. For AWS this is the  VPC, for AZURE this is the Vnet."`
	HostSubnet          string `json:"hostSubnet" description:"The subnet where the host is in."`
	Version             string `json:"version"  description:"The connector version"`
	ActiveSessionsCount int    `json:"activeSessionsCount" description:"How many active sessions currently running on this connector." ge:"0"`
	Status              string `json:"status" description:"The current connector status"`
	OS                  string `json:"os"  description:"The operating system of the connector host."`
	ProxySettings       string `json:"proxySettings"  description:"The HTTP Proxy details if configured."`
	IsLatestVersion     bool   `json:"isLatestVersion"  description:"Whether the connector is updated with the latest version."`
}

// IdsecSIAConnectorsListResponse represents the response for listing connectors in Idsec SIA.
type IdsecSIAConnectorsListResponse struct {
	Count             int                 `json:"count" `
	Items             []IdsecSIAConnector `json:"items" `
	ContinuationToken string              `json:"continuationToken" `
}
