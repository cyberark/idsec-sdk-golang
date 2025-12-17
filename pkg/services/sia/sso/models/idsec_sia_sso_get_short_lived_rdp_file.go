package models

// IdsecSIASSOGetShortLivedRDPFile is a struct that represents the request for getting a short-lived RDP file from the Idsec SIA SSO service.
type IdsecSIASSOGetShortLivedRDPFile struct {
	AllowCaching       bool   `json:"allow_caching" mapstructure:"allow_caching" flag:"allow-caching" desc:"Allow short lived token caching" default:"false"`
	Folder             string `json:"folder" validate:"required" mapstructure:"folder" flag:"folder" desc:"Output folder to write the rdp file to"`
	TargetAddress      string `json:"target_address" validate:"required" mapstructure:"target_address"`
	TargetDomain       string `json:"target_domain,omitempty" mapstructure:"target_domain,omitempty" flag:"target-domain" desc:"Target domain to use for the rdp file"`
	TargetUser         string `json:"target_user,omitempty" mapstructure:"target_user,omitempty" flag:"target-user" desc:"Target user to use for the rdp file"`
	ElevatedPrivileges bool   `json:"elevated_privileges" mapstructure:"elevated_privileges" flag:"elevated-privileges" desc:"Whether to use elevated privileges or not"`
}
