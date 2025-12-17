package auth

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// IdsecTokenType is a string type that represents the type of token used in the Idsec SIA.
type IdsecTokenType string

// Toke types supported by Idsec
const (
	JWT      IdsecTokenType = "JSON Web Token"
	Cookies  IdsecTokenType = "Cookies"
	Token    IdsecTokenType = "Token"
	Password IdsecTokenType = "Password"
	Custom   IdsecTokenType = "Custom"
	Internal IdsecTokenType = "Internal"
)

// IdsecSecret is a struct that represents a secret in the Idsec SIA.
type IdsecSecret struct {
	Secret string `json:"secret"`
}

// IdsecToken is a struct that represents a token in the Idsec SIA.
type IdsecToken struct {
	Token        string                  `json:"token" mapstructure:"token" validate:"required"`
	TokenType    IdsecTokenType          `json:"token_type" mapstructure:"token_type" validate:"required"`
	Username     string                  `json:"username" mapstructure:"username"`
	Endpoint     string                  `json:"endpoint" mapstructure:"endpoint"`
	AuthMethod   IdsecAuthMethod         `json:"auth_method" mapstructure:"auth_method"`
	ExpiresIn    common.IdsecRFC3339Time `json:"expires_in" mapstructure:"expires_in"`
	RefreshToken string                  `json:"refresh_token" mapstructure:"refresh_token"`
	Metadata     map[string]interface{}  `json:"metadata" mapstructure:"metadata"`
}
