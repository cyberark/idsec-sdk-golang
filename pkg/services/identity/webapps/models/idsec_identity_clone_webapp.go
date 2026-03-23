package models

// IdsecIdentityCloneWebapp represents the request body for cloning a webapp.
type IdsecIdentityCloneWebapp struct {
	WebappID   string `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp to clone"`
	WebappName string `json:"webapp_name" mapstructure:"webapp_name" flag:"webapp-name" desc:"Name of the webapp to clone"`
}
