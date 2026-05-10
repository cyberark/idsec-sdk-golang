package models

// IdsecIdentityGetRoleAttributes represents the response containing role attributes.
type IdsecIdentityGetRoleAttributes struct {
	RoleID string `json:"role_id" mapstructure:"role_id" flag:"role-id" desc:"ID of the role whose attributes are retrieved"`
}
