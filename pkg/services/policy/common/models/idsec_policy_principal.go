package models

// Possible types of principals that can be bound to a policy.
const (
	PrincipalTypeUser  = "USER"
	PrincipalTypeRole  = "ROLE"
	PrincipalTypeGroup = "GROUP"
)

// IdsecPolicyPrincipal represents a principal reference.
type IdsecPolicyPrincipal struct {
	ID                  string `json:"id" mapstructure:"id" flag:"id" desc:"The unique identifier of the identity in CyberArk. An identity is a user, group, or role. maxLength: 40" validate:"max=40"`
	Name                string `json:"name" mapstructure:"name" flag:"name" desc:"The name of the principal. minLength: 1" validate:"max=512,regexp=^[\\w.+\\-@#]+$"`
	SourceDirectoryName string `json:"source_directory_name,omitempty"  mapstructure:"source_directory_name,omitempty" flag:"source-directory-name" desc:"The name of the directory service. If the type is ROLE, then this field is optional. maxLength: 256." validate:"max=50,regexp=^\\w+$"`
	SourceDirectoryID   string `json:"source_directory_id,omitempty"  mapstructure:"source_directory_id,omitempty" flag:"source-directory-id" desc:"The unique identifier of the directory service. If the type is ROLE, then this field is optional."`
	Type                string `json:"type" mapstructure:"type" flag:"type" desc:"The type of principal" choices:"USER,ROLE,GROUP"`
}
