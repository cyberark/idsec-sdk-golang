package models

// IdsecIdentityGetWebappTemplate represents the request body for fetching a webapp template by its ID.
type IdsecIdentityGetWebappTemplate struct {
	WebappTemplateID   string `json:"webapp_template_id" mapstructure:"webapp_template_id" flag:"webapp-template-id" desc:"Unique identifier of the webapp template to fetch"`
	WebappTemplateName string `json:"webapp_template_name" mapstructure:"webapp_template_name" flag:"webapp-template-name" desc:"Name of the webapp template to fetch"`
}
