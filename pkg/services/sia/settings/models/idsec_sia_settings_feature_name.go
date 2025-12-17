package models

// IdsecSIASettingsFeatureName represents the available feature names for SIA settings configuration.
//
// These constants define the supported feature types that can be configured
// in the Idsec SIA service, including MFA caching for various protocols,
// certificate validation, file transfer capabilities, and access control features.
const (
	IdsecSIASettingsFeatureNameADBMfaCaching         = "ADB_MFA_CACHING"
	IdsecSIASettingsFeatureNameCertificateValidation = "CERTIFICATE_VALIDATION"
	IdsecSIASettingsFeatureNameK8SMfaCaching         = "K8S_MFA_CACHING"
	IdsecSIASettingsFeatureNameRDPFileTransfer       = "RDP_FILE_TRANSFER"
	IdsecSIASettingsFeatureNameRDPKeyboardLayout     = "RDP_KEYBOARD_LAYOUT"
	IdsecSIASettingsFeatureNameRDPMfaCaching         = "RDP_MFA_CACHING"
	IdsecSIASettingsFeatureNameRDPTokenMfaCaching    = "RDP_TOKEN_MFA_CACHING"
	IdsecSIASettingsFeatureNameRDPRecording          = "RDP_RECORDING"
	IdsecSIASettingsFeatureNameSSHMfaCaching         = "MFA_CACHING"
	IdsecSIASettingsFeatureNameSSHCommandAudit       = "SSH_COMMAND_AUDIT"
	IdsecSIASettingsFeatureNameStandingAccess        = "STANDING_ACCESS"
	IdsecSIASettingsFeatureNameLogonSequence         = "LOGON_SEQUENCE"
	IdsecSIASettingsFeatureNameSelfHostedPAM         = "SELF_HOSTED_PAM"
	IdsecSIASettingsFeatureNameRDPKerberosAuthMode   = "RDP_KERBEROS_AUTH_MODE"
	IdsecSIASettingsFeatureNameRDPTranscription      = "RDP_TRANSCRIPTION"
	IdsecSIASettingsFeatureNameSSHRecording          = "SSH_RECORDING"
)
