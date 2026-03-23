package models

// IdsecIdentityDeleteWebapp represents the request body for deleting a webapp.
type IdsecIdentityDeleteWebapp struct {
	WebappID   string `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp to delete"`
	WebappName string `json:"webapp_name" mapstructure:"webapp_name" flag:"webapp-name" desc:"Name of the webapp to delete"`
}
