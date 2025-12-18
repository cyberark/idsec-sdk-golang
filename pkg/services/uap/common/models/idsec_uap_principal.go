package models

// Possible types of principals in UAP.
const (
	PrincipalTypeUser  = "USER"
	PrincipalTypeRole  = "ROLE"
	PrincipalTypeGroup = "GROUP"
)

// IdsecUAPPrincipal represents a principal in UAP.
type IdsecUAPPrincipal struct {
	ID                  string `json:"id"  mapstructure:"id" flag:"id" desc:"The unique identifier of the principal in CyberArk. A principal is a user, group, or role. maxLength: 40" validate:"required,max=40"`
	Name                string `json:"name" mapstructure:"name" flag:"name" desc:"The name of the principal. minLength: 1" validate:"required,max=512,regexp=^[\\w.+\\-@#]+$"`
	SourceDirectoryName string `json:"source_directory_name,omitempty" mapstructure:"source_directory_name,omitempty" flag:"source-directory-name" desc:"The name of the directory service.(For Cloud console: if the type is ROLE, then this field is optional and maxLength:256)" validate:"max=256,regexp=^\\w+$"`
	SourceDirectoryID   string `json:"source_directory_id,omitempty" mapstructure:"source_directory_id,omitempty" flag:"source-directory-id" desc:"The unique identifier of the directory service. (For Cloud console: If the type is ROLE, then this field is optional.)"`
	Type                string `json:"type" validate:"required" mapstructure:"type" flag:"type" desc:"The type of the principal user, group or role" choices:"USER,ROLE,GROUP"`
}
