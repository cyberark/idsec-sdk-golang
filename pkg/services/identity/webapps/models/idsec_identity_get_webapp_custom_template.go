package models

// IdsecIdentityGetWebappCustomTemplate represents the request body for fetching a custom webapp template by its ID.
type IdsecIdentityGetWebappCustomTemplate struct {
	WebappTemplateID   string `json:"webapp_template_id" mapstructure:"webapp_template_id" flag:"webapp-template-id" desc:"Unique identifier of the custom webapp template to fetch"`
	WebappTemplateName string `json:"webapp_template_name" mapstructure:"webapp_template_name" flag:"webapp-template-name" desc:"Name of the custom webapp template to fetch"`
}
