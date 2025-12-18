package models

// IdsecSIASettings represents the complete configuration for Idsec SIA settings.
//
// This model contains all available configuration options for the Idsec SIA service,
// including MFA caching for different protocols (ADB, K8S, RDP, SSH), certificate validation,
// file transfer, keyboard layouts, recording, command auditing, standing access, and logon
// sequence settings. Unlike the set settings model, this represents the current state
// of all SIA configuration options and does not require validation for non-empty fields.
type IdsecSIASettings struct {
	AdbMfaCaching         *IdsecSIASettingsAdbMfaCaching         `json:"adb_mfa_caching,omitempty" mapstructure:"adb_mfa_caching,omitempty" flag:"adb-mfa-caching" desc:"The listSettings for ADB MFA caching."`
	CertificateValidation *IdsecSIASettingsCertificateValidation `json:"certificate_validation,omitempty" mapstructure:"certificate_validation,omitempty" flag:"certificate-validation" desc:"The listSettings for certificate validation."`
	K8sMfaCaching         *IdsecSIASettingsK8sMfaCaching         `json:"k8s_mfa_caching,omitempty" mapstructure:"k8s_mfa_caching,omitempty" flag:"k8s-mfa-caching" desc:"The listSettings for K8S MFA caching."`
	RdpFileTransfer       *IdsecSIASettingsRdpFileTransfer       `json:"rdp_file_transfer,omitempty" mapstructure:"rdp_file_transfer,omitempty" flag:"rdp-file-transfer" desc:"The listSettings for RDP file transfer."`
	RdpKeyboardLayout     *IdsecSIASettingsRdpKeyboardLayout     `json:"rdp_keyboard_layout,omitempty" mapstructure:"rdp_keyboard_layout,omitempty" flag:"rdp-keyboard-layout" desc:"The listSettings for RDP keyboard layout."`
	RdpMfaCaching         *IdsecSIASettingsRdpMfaCaching         `json:"rdp_mfa_caching,omitempty" mapstructure:"rdp_mfa_caching,omitempty" flag:"rdp-mfa-caching" desc:"The listSettings for RDP MFA caching."`
	RdpTokenMfaCaching    *IdsecSIASettingsRdpTokenMfaCaching    `json:"rdp_token_mfa_caching,omitempty" mapstructure:"rdp_token_mfa_caching,omitempty" flag:"rdp-token-mfa-caching" desc:"The listSettings for RDP token MFA caching."`
	RdpRecording          *IdsecSIASettingsRdpRecording          `json:"rdp_recording,omitempty" mapstructure:"rdp_recording,omitempty" flag:"rdp-recording" desc:"The listSettings for RDP recording."`
	SshMfaCaching         *IdsecSIASettingsSshMfaCaching         `json:"ssh_mfa_caching,omitempty" mapstructure:"ssh_mfa_caching,omitempty" flag:"ssh-mfa-caching" desc:"The listSettings for SSH MFA caching."`
	SshCommandAudit       *IdsecSIASettingsSshCommandAudit       `json:"ssh_command_audit,omitempty" mapstructure:"ssh_command_audit,omitempty" flag:"ssh-command-audit" desc:"The listSettings for SSH command audit."`
	StandingAccess        *IdsecSIASettingsStandingAccess        `json:"standing_access,omitempty" mapstructure:"standing_access,omitempty" flag:"standing-access" desc:"The listSettings for standing access."`
	LogonSequence         *IdsecSIASettingsLogonSequence         `json:"logon_sequence,omitempty" mapstructure:"logon_sequence,omitempty" flag:"logon-sequence" desc:"The listSettings for logon sequence."`
	SelfHostedPam         *IdsecSIASettingsSelfHostedPam         `json:"self_hosted_pam,omitempty" mapstructure:"self_hosted_pam,omitempty" flag:"self-hosted-pam" desc:"The listSettings for PAM Self-Hosted."`
	RdpKerberosAuthMode   *IdsecSIASettingsRdpKerberosAuthMode   `json:"rdp_kerberos_auth_mode,omitempty" mapstructure:"rdp_kerberos_auth_mode,omitempty" flag:"rdp-kerberos-auth-mode" desc:"The settings for RDP Kerberos auth mode."`
	RdpTranscription      *IdsecSIASettingsRdpTranscription      `json:"rdp_transcription,omitempty" mapstructure:"rdp_transcription,omitempty" flag:"rdp-transcription" desc:"The settings for RDP transcription."`
	SshRecording          *IdsecSIASettingsSshRecording          `json:"ssh_recording,omitempty" mapstructure:"ssh_recording,omitempty" flag:"ssh-recording" desc:"The settings for SSH recording."`
}
