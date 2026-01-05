package models

// IdsecIdentityCreateUser represents the schema for creating a user.
type IdsecIdentityCreateUser struct {
	Username                string `json:"username" mapstructure:"username" flag:"username" desc:"Name of the user to create" validate:"required"`
	DisplayName             string `json:"display_name,omitempty" mapstructure:"display_name" flag:"display-name" desc:"Display name of the user"`
	Email                   string `json:"email" mapstructure:"email" flag:"email" desc:"Email of the user" validate:"required,email"`
	MobileNumber            string `json:"mobile_number,omitempty" mapstructure:"mobile_number" flag:"mobile-number" desc:"Mobile number of the user"`
	Suffix                  string `json:"suffix,omitempty" mapstructure:"suffix" flag:"suffix" desc:"Suffix to use for the username, will use the default tenant one if not given"`
	Password                string `json:"password" mapstructure:"password" flag:"password" desc:"Password of the user"`
	InEverybodyRole         *bool  `json:"in_everybody_role,omitempty" mapstructure:"in_everybody_role" flag:"in-everybody-role" desc:"Whether to add the user to the 'Everybody' role"`
	InSysAdminRole          *bool  `json:"in_sysadmin_role,omitempty" mapstructure:"in_sysadmin_role" flag:"in-sysadmin-role" desc:"Whether to add the user to the 'SysAdmin' role"`
	ForcePasswordChangeNext *bool  `json:"force_password_change_next,omitempty" mapstructure:"force_password_change_next" flag:"force-password-change-next" desc:"Whether to force the user to change their password on next login"`
	SendEmailInvite         *bool  `json:"send_email_invite,omitempty" mapstructure:"send_email_invite" flag:"send-email-invite" desc:"Whether to send an email invite to the user upon creation"`
	SendSmsInvite           *bool  `json:"send_sms_invite,omitempty" mapstructure:"send_sms_invite" flag:"send-sms-invite" desc:"Whether to send an SMS invite to the user upon creation"`
}
