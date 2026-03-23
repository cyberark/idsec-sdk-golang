package models

// IdsecIdentityGetWebapp represents the request body for fetching a specific webapp by ID or name.
type IdsecIdentityGetWebapp struct {
	WebappID   string `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp to fetch"`
	WebappName string `json:"webapp_name" mapstructure:"webapp_name" flag:"webapp-name" desc:"Name of the webapp to fetch"`
}
