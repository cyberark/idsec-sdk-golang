package models

// IdsecIdentityImportWebapp represents the request body for importing a webapp from a template.
type IdsecIdentityImportWebapp struct {
	IdsecIdentityWebappAppsConfiguration   `mapstructure:",squash"`
	IdsecIdentityWebappPolicyConfiguration `mapstructure:",squash"`
	TemplateName                           string  `json:"template_name" mapstructure:"template_name" flag:"template-name" desc:"Name of the template to import" validate:"required,min=1"`
	WebappName                             *string `json:"webapp_name,omitempty" mapstructure:"webapp_name,omitempty" flag:"webapp-name" desc:"New name of the webapp to update"`
	ServiceName                            *string `json:"service_name,omitempty" mapstructure:"service_name,omitempty" flag:"service-name" desc:"Name of the service to which the webapp belongs"`
	Description                            *string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"Description of the webapp"`
}
