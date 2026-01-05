package models

// IdsecIdentityUpdateUser represents the schema for updating a user's details.
type IdsecIdentityUpdateUser struct {
	UserID                  string `json:"user_id,omitempty" mapstructure:"user_id" flag:"user-id" desc:"Users id that we change the details for"`
	Username                string `json:"username,omitempty" mapstructure:"username" flag:"username" desc:"Username that we change the details for"`
	DisplayName             string `json:"display_name,omitempty" mapstructure:"display_name" flag:"display-name" desc:"Display name of the user to change"`
	Email                   string `json:"email,omitempty" mapstructure:"email" flag:"email" desc:"Email of the user to change"`
	MobileNumber            string `json:"mobile_number,omitempty" mapstructure:"mobile_number" flag:"mobile-number" desc:"Mobile number of the user to change"`
	InEverybodyRole         *bool  `json:"in_everybody_role,omitempty" mapstructure:"in_everybody_role" flag:"in-everybody-role" desc:"Whether to add the user to the 'Everybody' role"`
	InSysAdminRole          *bool  `json:"in_sysadmin_role,omitempty" mapstructure:"in_sysadmin_role" flag:"in-sysadmin-role" desc:"Whether to add the user to the 'SysAdmin' role"`
	ForcePasswordChangeNext *bool  `json:"force_password_change_next,omitempty" mapstructure:"force_password_change_next" flag:"force-password-change-next" desc:"Whether to force the user to change their password on next login"`
	SendEmailInvite         *bool  `json:"send_email_invite,omitempty" mapstructure:"send_email_invite" flag:"send-email-invite" desc:"Whether to send an email invite to the user upon creation"`
	SendSmsInvite           *bool  `json:"send_sms_invite,omitempty" mapstructure:"send_sms_invite" flag:"send-sms-invite" desc:"Whether to send an SMS invite to the user upon creation"`
}
