package models

// IdsecIdentityGetWebappPermissions represents the request body for fetching the permissions of a specific webapp by ID or name.
type IdsecIdentityGetWebappPermissions struct {
	WebappID   string `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp to fetch its permissions"`
	WebappName string `json:"webapp_name" mapstructure:"webapp_name" flag:"webapp-name" desc:"Name of the webapp to fetch its permissions"`
}

// IdsecIdentityGetWebappPermission represents the request body for fetching a specific permission of a webapp by the principal and principal type.
type IdsecIdentityGetWebappPermission struct {
	WebappID      string  `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp to fetch its permissions"`
	WebappName    string  `json:"webapp_name" mapstructure:"webapp_name" flag:"webapp-name" desc:"Name of the webapp to fetch its permissions"`
	Principal     *string `json:"principal" mapstructure:"principal" flag:"principal" desc:"Principal Name of the grant"`
	PrincipalType string  `json:"principal_type" mapstructure:"principal_type" flag:"principal-type" desc:"Principal type of the grant" choices:"User,Group,Role" validate:"required"`
	PrincipalId   *string `json:"principal_id" mapstructure:"principal_id" flag:"principal-id" desc:"Principal ID of the grant"`
}
