package models

import "fmt"

// Possible types of principals that can be bound to a policy.
const (
	PrincipalTypeUser  = "USER"
	PrincipalTypeRole  = "ROLE"
	PrincipalTypeGroup = "GROUP"
)

// IdsecPolicyPrincipal represents a principal reference.
type IdsecPolicyPrincipal struct {
	ID                  string `json:"id" validate:"required,max=40" mapstructure:"id" flag:"id" desc:"The unique identifier of the identity in Idira. An identity is a user, group, or role. maxLength: 40"`
	Name                string `json:"name" validate:"required,max=512,regexp=^[\\w.+\\-@#]+$" mapstructure:"name" flag:"name" desc:"The name of the principal. minLength: 1"`
	SourceDirectoryName string `json:"source_directory_name,omitempty"  mapstructure:"source_directory_name,omitempty" flag:"source-directory-name" desc:"The name of the directory service. Required unless type is ROLE. maxLength: 256." validate:"max=50,regexp=^\\w+$"`
	SourceDirectoryID   string `json:"source_directory_id,omitempty"  mapstructure:"source_directory_id,omitempty" flag:"source-directory-id" desc:"The unique identifier of the directory service. Required unless type is ROLE."`
	Type                string `json:"type" validate:"required" mapstructure:"type" flag:"type" desc:"The type of principal" choices:"USER,ROLE,GROUP"`
}

// Validate enforces the conditional requirement that SourceDirectoryName and
// SourceDirectoryID must be supplied for every principal type except ROLE
func (p *IdsecPolicyPrincipal) Validate() error {
	if p.Type == PrincipalTypeRole {
		return nil
	}
	if p.SourceDirectoryName == "" {
		return fmt.Errorf("source_directory_name is required when type is %q", p.Type)
	}
	if p.SourceDirectoryID == "" {
		return fmt.Errorf("source_directory_id is required when type is %q", p.Type)
	}
	return nil
}
