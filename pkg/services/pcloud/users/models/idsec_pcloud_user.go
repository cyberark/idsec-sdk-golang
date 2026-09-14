package models

// IdsecPCloudUser represents the full state of a Vault user returned by the PVWA Users API.
type IdsecPCloudUser struct {
	UserID                int    `json:"user_id" mapstructure:"user_id" desc:"Unique numeric ID of the Vault user" flag:"user-id"`
	Username              string `json:"username" mapstructure:"username" desc:"Vault username" flag:"username" validate:"required"`
	UserType              string `json:"user_type" mapstructure:"user_type" desc:"Vault user type (e.g. AppProvider)" flag:"user-type"`
	Location              string `json:"location" mapstructure:"location" desc:"Vault location path for the user" flag:"location"`
	EnableUser            *bool  `json:"enable_user" mapstructure:"enable_user" desc:"Whether the user account is enabled" flag:"enable-user"`
	ChangePassOnNextLogon *bool  `json:"change_pass_on_next_logon" mapstructure:"change_pass_on_next_logon" desc:"Whether the user must change password on next logon" flag:"change-pass-on-next-logon"`
	PasswordNeverExpires  *bool  `json:"password_never_expires" mapstructure:"password_never_expires" desc:"Whether the user's password never expires" flag:"password-never-expires"`
}
