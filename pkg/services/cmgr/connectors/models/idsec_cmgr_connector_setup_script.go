package models

// IdsecCmgrSetupScript represents the response from the api/setup-script endpoint.
type IdsecCmgrSetupScript struct {
	Script string `json:"script" mapstructure:"script" desc:"The installation script for the management agent connector."`
}
