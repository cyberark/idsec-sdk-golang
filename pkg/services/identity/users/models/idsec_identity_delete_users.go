package models

// IdsecIdentityDeleteUsers represents the schema for deleting multiple users.
type IdsecIdentityDeleteUsers struct {
	UserIDs []string `json:"user_ids" mapstructure:"user_ids" flag:"user-ids" desc:"User IDs to delete" required:"true"`
}
