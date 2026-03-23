package models

// IdsecIdentityUpdateWebapp represents the request body for updating a webapp.
type IdsecIdentityUpdateWebapp struct {
	IdsecIdentityWebappAppsConfiguration   `mapstructure:",squash"`
	IdsecIdentityWebappPolicyConfiguration `mapstructure:",squash"`
	WebappID                               string  `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp" validate:"required,min=1"`
	WebappName                             *string `json:"webapp_name,omitempty" mapstructure:"webapp_name,omitempty" flag:"webapp-name" desc:"New name of the webapp to update"`
	ServiceName                            *string `json:"service_name,omitempty" mapstructure:"service_name,omitempty" flag:"service-name" desc:"Name of the service to which the webapp belongs"`
	Description                            *string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"Description of the webapp"`
}
