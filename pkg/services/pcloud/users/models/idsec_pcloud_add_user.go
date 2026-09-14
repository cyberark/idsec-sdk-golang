package models

// IdsecPCloudAddUser represents the input for creating a new Vault user via POST /PasswordVault/api/Users.
type IdsecPCloudAddUser struct {
	Username              string `json:"username" mapstructure:"username" flag:"username" desc:"Vault username" validate:"required"`
	InitialPassword       string `json:"initial_password" mapstructure:"initial_password" flag:"initial-password" desc:"Initial password for the user (max 39 characters)" validate:"required,max=39" secret:"true"`
	UserType              string `json:"user_type" mapstructure:"user_type" flag:"user-type" desc:"Vault user type (e.g. AppProvider)" validate:"required"`
	Location              string `json:"location" mapstructure:"location" flag:"location" desc:"Vault location path for the user (e.g. \\)" validate:"required"`
	EnableUser            *bool  `json:"enable_user,omitempty" mapstructure:"enable_user" flag:"enable-user" desc:"Whether the user account is enabled" default:"true"`
	ChangePassOnNextLogon *bool  `json:"change_pass_on_next_logon,omitempty" mapstructure:"change_pass_on_next_logon" flag:"change-pass-on-next-logon" desc:"Whether the user must change password on next logon" default:"true"`
	PasswordNeverExpires  *bool  `json:"password_never_expires,omitempty" mapstructure:"password_never_expires" flag:"password-never-expires" desc:"Whether the user's password never expires" default:"true"`
}
