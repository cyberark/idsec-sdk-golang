package models

// IdsecSIASSOAcquireTokenResponse is a struct that represents the response from the Idsec SIA SSO service for acquiring a token.
type IdsecSIASSOAcquireTokenResponse struct {
	Token    map[string]interface{} `json:"token" validate:"required" mapstructure:"token"`
	Metadata map[string]interface{} `json:"metadata" validate:"required" mapstructure:"metadata"`
}
