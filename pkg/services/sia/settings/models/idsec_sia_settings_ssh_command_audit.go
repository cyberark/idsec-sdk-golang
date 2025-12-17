package models

// IdsecSIASettingsSshCommandAudit represents the SSH command audit configuration for SIA settings.
//
// This model contains configuration options for SSH command auditing capabilities
// in the Idsec SIA service. It defines whether command parsing for audit purposes
// is enabled and specifies the shell prompt pattern used during audit operations
// to properly parse and track SSH commands executed during sessions.
type IdsecSIASettingsSshCommandAudit struct {
	IsCommandParsingForAuditEnabled *bool   `json:"is_command_parsing_for_audit_enabled,omitempty" mapstructure:"is_command_parsing_for_audit_enabled,omitempty" flag:"is-command-parsing-for-audit-enabled" desc:"Whether command parsing for audit is enabled"`
	ShellPromptForAudit             *string `json:"shell_prompt_for_audit,omitempty" mapstructure:"shell_prompt_for_audit,omitempty" flag:"shell-prompt-for-audit" desc:"The shell prompt used for audit"`
}
