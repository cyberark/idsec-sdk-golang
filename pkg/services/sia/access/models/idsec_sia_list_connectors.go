package models

// IdsecSIAConnector represents the schema for a connector in Idsec SIA.
// JSON keys are camelCase (server format); mapstructure keys are snake_case
// because ListConnectors runs the response through DeserializeJSONSnake before
// calling mapstructure.Decode.
type IdsecSIAConnector struct {
	ID                               string `json:"id" mapstructure:"id" min_length:"2" description:"The connector ID."`
	WorkspaceID                      string `json:"workspaceId" mapstructure:"workspace_id" description:"The workspace ID of the connector host. It is relevant only for the following connector_host_type: AWS (the AWS Account ID) and AZURE (the subscription ID)."` //nolint:tagliatelle
	HostInstanceID                   string `json:"hostInstanceId" mapstructure:"host_instance_id" description:"The host ID. For AWS, it is the Instance ID. For Azure, it is the VM resource ID."`                                                                     //nolint:tagliatelle
	Region                           string `json:"region" mapstructure:"region" description:"The region where the connector host is located."`
	HostIP                           string `json:"hostIp" mapstructure:"host_ip" description:"The host machine."`                                                                             //nolint:tagliatelle
	HostName                         string `json:"hostName" mapstructure:"host_name" description:"The host name."`                                                                            //nolint:tagliatelle
	HostType                         string `json:"hostType" mapstructure:"host_type" description:"The platform type of the host. Valid values: AWS, AZURE or ON-PREMISE."`                    //nolint:tagliatelle
	HostNetwork                      string `json:"hostNetwork" mapstructure:"host_network" description:"The virtual network of the host. For AWS, it is the VPC. For AZURE, it is the Vnet."` //nolint:tagliatelle
	HostSubnet                       string `json:"hostSubnet" mapstructure:"host_subnet" description:"The subnet of the host."`                                                               //nolint:tagliatelle
	Version                          string `json:"version" mapstructure:"version" description:"The connector version."`
	ActiveSessionsCount              int    `json:"activeSessionsCount" mapstructure:"active_sessions_count" description:"The number of active sessions currently running on the connector." ge:"0"` //nolint:tagliatelle
	Status                           string `json:"status" mapstructure:"status" description:"The connector's current status."`
	OS                               string `json:"os" mapstructure:"os" description:"The operating system of the connector host."`
	ProxySettings                    string `json:"proxySettings" mapstructure:"proxy_settings" description:"The HTTP Proxy details, if configured."`                                                                                                //nolint:tagliatelle
	IsLatestVersion                  bool   `json:"isLatestVersion" mapstructure:"is_latest_version" description:"Indicates whether the connector is updated with the latest version."`                                                              //nolint:tagliatelle
	LastRotationJobStatus            string `json:"last_rotation_job_status,omitempty" mapstructure:"last_rotation_job_status" description:"The status of the last certificate rotation job, if one exists. (e.g. SUCCEEDED, FAILED, IN_PROGRESS)."` //nolint:tagliatelle
	LastRotationJobErrorCode         string `json:"last_rotation_job_error_code,omitempty" mapstructure:"last_rotation_job_error_code" description:"The error code of the last certificate rotation job, if one exists."`                            //nolint:tagliatelle
	LastRotationJobInfoUpdateDate    string `json:"last_rotation_job_info_update_date,omitempty" mapstructure:"last_rotation_job_info_update_date" description:"The last time the rotation job status was updated, if one exists."`                  //nolint:tagliatelle
	LastSuccessRotationDate          string `json:"last_success_rotation_date,omitempty" mapstructure:"last_success_rotation_date" description:"The date of the last successful certificate rotation, if one exists."`                               //nolint:tagliatelle
	LastRotationJobStatusDescription string `json:"last_rotation_job_status_description,omitempty" mapstructure:"last_rotation_job_status_description" description:"The description of the last certificate rotation job error, if one exists."`     //nolint:tagliatelle
}

// IdsecSIAConnectorsListResponse represents the response for listing connectors in Idsec SIA.
type IdsecSIAConnectorsListResponse struct {
	Count             int                 `json:"count" `
	Items             []IdsecSIAConnector `json:"items" `
	ContinuationToken string              `json:"continuationToken" ` //nolint:tagliatelle
}
