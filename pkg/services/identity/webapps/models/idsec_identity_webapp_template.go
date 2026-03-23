package models

// IdsecIdentityWebappTemplate represents a webapp template as returned by the Identity API.
type IdsecIdentityWebappTemplate struct {
	WebappTemplateID      string  `json:"webapp_template_id" mapstructure:"webapp_template_id" flag:"webapp-template-id" desc:"Unique identifier of the webapp template" validate:"required,min=1"`
	WebappTemplateName    string  `json:"webapp_template_name" mapstructure:"webapp_template_name" flag:"webapp-template-name" desc:"Name of the webapp template" validate:"required,min=1"`
	Category              *string `json:"category" mapstructure:"category" flag:"category" desc:"Category of the webapp template"`
	DisplayName           string  `json:"display_name" mapstructure:"display_name" flag:"display-name" desc:"Display name of the webapp template"`
	AppTypeDisplayName    string  `json:"app_type_display_name" mapstructure:"app_type_display_name" flag:"app-type-display-name" desc:"Display name of the app type"`
	Description           string  `json:"description" mapstructure:"description" flag:"description" desc:"Description of the webapp template"`
	Version               *string `json:"version,omitempty" mapstructure:"version,omitempty" flag:"version" desc:"Version of the webapp template"`
	WebappLoginType       *string `json:"webapp_login_type,omitempty" mapstructure:"webapp_login_type,omitempty" flag:"webapp-login-type" desc:"Web app login type"`
	AppType               string  `json:"app_type" mapstructure:"app_type" flag:"app-type" desc:"Type of the app"`
	ServiceName           *string `json:"service_name,omitempty" mapstructure:"service_name,omitempty" flag:"service-name" desc:"Service name associated with the template"`
	WebappTypeDisplayName string  `json:"webapp_type_display_name" mapstructure:"webapp_type_display_name" flag:"webapp-type-display-name" desc:"Display name of the web app type"`
	UserNameStrategy      *string `json:"user_name_strategy" mapstructure:"user_name_strategy" flag:"user-name-strategy" desc:"User name strategy"`
	TemplateName          *string `json:"template_name,omitempty" mapstructure:"template_name,omitempty" flag:"template-name" desc:"Name of the template"`
	IsSwsEnabled          *bool   `json:"is_sws_enabled,omitempty" mapstructure:"is_sws_enabled,omitempty" flag:"is-sws-enabled" desc:"Whether SWS is enabled"`
	IsScaEnabled          *bool   `json:"is_sca_enabled,omitempty" mapstructure:"is_sca_enabled,omitempty" flag:"is-sca-enabled" desc:"Whether SCA is enabled"`
	Generic               *bool   `json:"generic,omitempty" mapstructure:"generic,omitempty" flag:"generic" desc:"Whether the template is generic"`
}
