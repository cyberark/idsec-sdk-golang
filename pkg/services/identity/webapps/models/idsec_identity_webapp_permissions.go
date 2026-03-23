package models

// Possible principal types
const (
	PrincipalTypeUser  = "User"
	PrincipalTypeGroup = "Group"
	PrincipalTypeRole  = "Role"
)

// Possible grant types
const (
	GrantRightNone       = "None"
	GrantRightView       = "View"
	GrantRightViewDetail = "ViewDetail"
	GrantRightAdmin      = "Admin"
	GrantRightGrant      = "Grant"
	GrantRightExecute    = "Execute"
	GrantRightAutomatic  = "Automatic"
	GrantRightDelete     = "Delete"
)

// IdsecIdentityWebappGrant represents the grant result for a webapp.
type IdsecIdentityWebappGrant struct {
	DirectoryServiceUuid *string  `json:"directory_service_uuid,omitempty" mapstructure:"directory_service_uuid,omitempty" flag:"directory-service-uuid" desc:"Directory service UUID of the grant, if applicable"`
	ExternalUuid         *string  `json:"external_uuid,omitempty" mapstructure:"external_uuid,omitempty" flag:"external-uuid" desc:"External UUID of the grant, if applicable"`
	SystemName           *string  `json:"system_name,omitempty" mapstructure:"system_name,omitempty" flag:"system-name" desc:"System name of the grant, if applicable"`
	PrincipalId          *string  `json:"principal_id" mapstructure:"principal_id" flag:"principal-id" desc:"Principal ID of the grant"`
	Type                 *string  `json:"type,omitempty" mapstructure:"type,omitempty" flag:"type" desc:"Type of the grant"`
	Principal            string   `json:"principal" mapstructure:"principal" flag:"principal" desc:"Principal Name of the grant"`
	PrincipalType        string   `json:"principal_type" mapstructure:"principal_type" flag:"principal-type" desc:"Principal type of the grant" choices:"User,Group,Role"`
	Rights               []string `json:"rights" mapstructure:"rights" flag:"rights" desc:"List of rights in the grant" validate:"required" choices:"None,View,ViewDetail,Admin,Grant,Execute,Automatic,Delete"`
}

// IdsecIdentityWebappPermissions represents the grants result for a webapp.
type IdsecIdentityWebappPermissions struct {
	WebappID string                     `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp"`
	Grants   []IdsecIdentityWebappGrant `json:"grants" mapstructure:"grants" flag:"grants" desc:"List of grants" validate:"required"`
}

// IdsecIdentityWebappPermission represents a single grant result for a webapp.
type IdsecIdentityWebappPermission struct {
	IdsecIdentityWebappGrant `mapstructure:",squash"`
	WebappID                 string `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp"`
}
