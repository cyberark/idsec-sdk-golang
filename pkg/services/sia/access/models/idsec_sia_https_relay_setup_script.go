// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIAHTTPSRelaySetupScript represents the setup script response for an HTTPS relay installation.
type IdsecSIAHTTPSRelaySetupScript struct {
	ScriptURL string `json:"script_url,omitempty" mapstructure:"script_url,omitempty" desc:"The URL of the setup script."`
	BashCmd   string `json:"bash_cmd,omitempty" mapstructure:"bash_cmd,omitempty" desc:"The bash command to run the setup script."`
}
