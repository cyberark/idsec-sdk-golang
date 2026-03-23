package models

// IdsecIdentitySetWebappPermissions represents the request body for setting permissions of a webapp.
type IdsecIdentitySetWebappPermissions struct {
	WebappID   string                     `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp to set the permissions for"`
	WebappName string                     `json:"webapp_name" mapstructure:"webapp_name" flag:"webapp-name" desc:"Name of the webapp to set the permissions for"`
	Grants     []IdsecIdentityWebappGrant `json:"grants" mapstructure:"grants" flag:"grants" desc:"List of grants to set for the webapp" validate:"required"`
}

// IdsecIdentitySetWebappPermission represents the request body for setting a single permission of a webapp.
type IdsecIdentitySetWebappPermission struct {
	IdsecIdentityWebappGrant `mapstructure:",squash"`
	WebappID                 string `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp to set the permission for"`
	WebappName               string `json:"webapp_name" mapstructure:"webapp_name" flag:"webapp-name" desc:"Name of the webapp to set the permission for"`
}
