package models

import "github.com/cyberark/idsec-sdk-golang/pkg/models/common/identity"

// Possible entity types
const (
	EntityTypeRole  = "ROLE"
	EntityTypeUser  = "USER"
	EntityTypeGroup = "GROUP"
)

// IdsecIdentityEntity is an interface that defines the methods for an identity entity.
type IdsecIdentityEntity interface {
	GetEntityType() string
}

// IdsecIdentityBaseEntity represents the schema for an identity entity.
type IdsecIdentityBaseEntity struct {
	IdsecIdentityEntity      `json:"-" mapstructure:"-"`
	ID                       string `json:"id" mapstructure:"id" flag:"id" desc:"ID of the entity" required:"true"`
	Name                     string `json:"name" mapstructure:"name" flag:"name" desc:"Name of the entity" required:"true"`
	EntityType               string `json:"entity_type" mapstructure:"entity_type" flag:"entity-type" desc:"Type of the entity" required:"true" choices:"USER,ROLE,GROUP"`
	DirectoryServiceType     string `json:"directory_service_type" mapstructure:"directory_service_type" flag:"directory-service-type" desc:"Directory type of the entity" required:"true" choices:"AdProxy,CDS,FDS"`
	DisplayName              string `json:"display_name,omitempty" mapstructure:"display_name" flag:"display-name" desc:"Display name of the entity"`
	ServiceInstanceLocalized string `json:"service_instance_localized" mapstructure:"service_instance_localized" flag:"service-instance-localized" desc:"Display directory service name" required:"true"`
}

// GetEntityType returns the entity type of the IdsecIdentityUserEntity.
func (a *IdsecIdentityBaseEntity) GetEntityType() string {
	return a.EntityType
}

// IdsecIdentityUserEntity represents the schema for a user entity.
type IdsecIdentityUserEntity struct {
	IdsecIdentityBaseEntity
	Email       string `json:"email,omitempty" mapstructure:"email" flag:"email" desc:"Email of the user"`
	Description string `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Description of the user"`
}

// IdsecIdentityGroupEntity represents the schema for a group entity.
type IdsecIdentityGroupEntity struct {
	IdsecIdentityBaseEntity
}

// GetEntityType returns the entity type of the IdsecIdentityGroupEntity.
func (a *IdsecIdentityGroupEntity) GetEntityType() string {
	return a.EntityType
}

// IdsecIdentityRoleEntity represents the schema for a role entity.
type IdsecIdentityRoleEntity struct {
	IdsecIdentityBaseEntity
	AdminRights []identity.RoleAdminRight `json:"admin_rights,omitempty" mapstructure:"admin_rights" flag:"admin-rights" desc:"Admin rights of the role"`
	IsHidden    bool                      `json:"is_hidden" mapstructure:"is_hidden" flag:"is-hidden" desc:"Whether this role is hidden or not" required:"true"`
	Description string                    `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Description of the role"`
}

// GetEntityType returns the entity type of the IdsecIdentityRoleEntity.
func (a *IdsecIdentityRoleEntity) GetEntityType() string {
	return a.EntityType
}
