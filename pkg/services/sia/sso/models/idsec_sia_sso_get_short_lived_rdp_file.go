package models

// IdsecSIASSOGetShortLivedRDPFile is a struct that represents the request for getting a short-lived RDP file from the Idsec SIA SSO service.
type IdsecSIASSOGetShortLivedRDPFile struct {
	AllowCaching       bool   `json:"allow_caching" mapstructure:"allow_caching" flag:"allow-caching" desc:"Indicates whether to allow short-lived token caching." default:"false"`
	Folder             string `json:"folder" validate:"required" mapstructure:"folder" flag:"folder" desc:"The output folder to which the RDP file is written."`
	TargetAddress      string `json:"target_address" validate:"required" mapstructure:"target_address"`
	TargetDomain       string `json:"target_domain,omitempty" mapstructure:"target_domain,omitempty" flag:"target-domain" desc:"The target domain to use for the RDP file."`
	TargetUser         string `json:"target_user,omitempty" mapstructure:"target_user,omitempty" flag:"target-user" desc:"The target user to use for the RDP file."`
	VaultedAccountID   string `json:"vaulted_account_id,omitempty" mapstructure:"vaulted_account_id,omitempty" flag:"vaulted-account-id" desc:"The optional ID of the vaulted account to connect with, in the <safe id>_<account id> format. When given, a target user must be given as well, as the account is selected for that user." validate:"omitempty,excluded_without=TargetUser,regexp=^[0-9]+_[0-9]+$"`
	ElevatedPrivileges bool   `json:"elevated_privileges" mapstructure:"elevated_privileges" flag:"elevated-privileges" desc:"Indicates whether to use elevated privileges."`
}
