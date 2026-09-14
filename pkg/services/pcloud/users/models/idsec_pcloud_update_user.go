package models

// IdsecPCloudUpdateUser represents the input for updating an existing Vault user via PUT /PasswordVault/api/Users/{id}.
type IdsecPCloudUpdateUser struct {
	UserID                int    `json:"user_id" mapstructure:"user_id" flag:"user-id" desc:"Numeric ID of the Vault user to update" validate:"required"`
	Username              string `json:"username" mapstructure:"username" flag:"username" desc:"Vault username" validate:"required"`
	EnableUser            *bool  `json:"enable_user,omitempty" mapstructure:"enable_user" flag:"enable-user" desc:"Whether the user account is enabled"`
	ChangePassOnNextLogon *bool  `json:"change_pass_on_next_logon,omitempty" mapstructure:"change_pass_on_next_logon" flag:"change-pass-on-next-logon" desc:"Whether the user must change password on next logon"`
	PasswordNeverExpires  *bool  `json:"password_never_expires,omitempty" mapstructure:"password_never_expires" flag:"password-never-expires" desc:"Whether the user's password never expires"`
}
