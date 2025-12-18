package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	settingsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings/models"
)

// TerraformActionSettingsResource is a struct that defines the SIA ListSettings general resource action.
var TerraformActionSettingsResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-settings",
			ActionDescription: "The SIA ListSettings resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettings{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-settings",
		actions.ReadOperation:   "list-settings",
		actions.UpdateOperation: "set-settings",
	},
}

// TerraformActionAdbMfaCachingSettingResource is a struct that defines the SIA ADB MFA Caching setting resource action.
var TerraformActionAdbMfaCachingSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-adb-mfa-caching",
			ActionDescription: "The SIA ADB MFA caching resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsAdbMfaCaching{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-adb-mfa-caching",
		actions.ReadOperation:   "adb-mfa-caching",
		actions.UpdateOperation: "set-adb-mfa-caching",
	},
}

// TerraformActionCertificateValidationSettingResource is a struct that defines the SIA Certificate Validation setting resource action.
var TerraformActionCertificateValidationSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-certificate-validation",
			ActionDescription: "The SIA certificate validation resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsCertificateValidation{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-certificate-validation",
		actions.ReadOperation:   "certificate-validation",
		actions.UpdateOperation: "set-certificate-validation",
	},
}

// TerraformActionK8sMfaCachingSettingResource is a struct that defines the SIA K8S MFA Caching setting resource action.
var TerraformActionK8sMfaCachingSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-k8s-mfa-caching",
			ActionDescription: "The SIA Kubernetes (K8S) MFA caching resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsK8sMfaCaching{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-k8s-mfa-caching",
		actions.ReadOperation:   "k8s-mfa-caching",
		actions.UpdateOperation: "set-k8s-mfa-caching",
	},
}

// TerraformActionRdpFileTransferSettingResource is a struct that defines the SIA RDP File Transfer setting resource action.
var TerraformActionRdpFileTransferSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-file-transfer",
			ActionDescription: "The SIA RDP file transfer resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpFileTransfer{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-rdp-file-transfer",
		actions.ReadOperation:   "rdp-file-transfer",
		actions.UpdateOperation: "set-rdp-file-transfer",
	},
}

// TerraformActionRdpKeyboardLayoutSettingResource is a struct that defines the SIA RDP Keyboard Layout setting resource action.
var TerraformActionRdpKeyboardLayoutSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-keyboard-layout",
			ActionDescription: "The SIA RDP keyboard layout resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpKeyboardLayout{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-rdp-keyboard-layout",
		actions.ReadOperation:   "rdp-keyboard-layout",
		actions.UpdateOperation: "set-rdp-keyboard-layout",
	},
}

// TerraformActionRdpMfaCachingSettingResource is a struct that defines the SIA RDP MFA Caching setting resource action.
var TerraformActionRdpMfaCachingSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-mfa-caching",
			ActionDescription: "The SIA RDP MFA caching resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpMfaCaching{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-rdp-mfa-caching",
		actions.ReadOperation:   "rdp-mfa-caching",
		actions.UpdateOperation: "set-rdp-mfa-caching",
	},
}

// TerraformActionRdpTokenMfaCachingSettingResource is a struct that defines the SIA RDP Token MFA Caching setting resource action.
var TerraformActionRdpTokenMfaCachingSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-token-mfa-caching",
			ActionDescription: "The SIA RDP token MFA caching resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpTokenMfaCaching{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-rdp-token-mfa-caching",
		actions.ReadOperation:   "rdp-token-mfa-caching",
		actions.UpdateOperation: "set-rdp-token-mfa-caching",
	},
}

// TerraformActionRdpRecordingSettingResource is a struct that defines the SIA RDP Recording setting resource action.
var TerraformActionRdpRecordingSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-recording",
			ActionDescription: "The SIA RDP recording resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpRecording{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-rdp-recording",
		actions.ReadOperation:   "rdp-recording",
		actions.UpdateOperation: "set-rdp-recording",
	},
}

// TerraformActionSshMfaCachingSettingResource is a struct that defines the SIA SSH MFA Caching setting resource action.
var TerraformActionSshMfaCachingSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-ssh-mfa-caching",
			ActionDescription: "The SIA SSH MFA caching resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsSshMfaCaching{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-ssh-mfa-caching",
		actions.ReadOperation:   "ssh-mfa-caching",
		actions.UpdateOperation: "set-ssh-mfa-caching",
	},
}

// TerraformActionSshCommandAuditSettingResource is a struct that defines the SIA SSH Command Audit setting resource action.
var TerraformActionSshCommandAuditSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-ssh-command-audit",
			ActionDescription: "The SIA SSH command audit resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsSshCommandAudit{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-ssh-command-audit",
		actions.ReadOperation:   "ssh-command-audit",
		actions.UpdateOperation: "set-ssh-command-audit",
	},
}

// TerraformActionStandingAccessSettingResource is a struct that defines the SIA Standing Access setting resource action.
var TerraformActionStandingAccessSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-standing-access",
			ActionDescription: "The SIA standing access resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsStandingAccess{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-standing-access",
		actions.ReadOperation:   "standing-access",
		actions.UpdateOperation: "set-standing-access",
	},
}

// TerraformActionLogonSequenceSettingResource is a struct that defines the SIA Logon Sequence setting resource action.
var TerraformActionLogonSequenceSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-logon-sequence",
			ActionDescription: "The SIA logon sequence resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsLogonSequence{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-logon-sequence",
		actions.ReadOperation:   "logon-sequence",
		actions.UpdateOperation: "set-logon-sequence",
	},
}

// TerraformActionSelfHostedPAMSettingResource is a struct that defines the SIA Self-Hosted PAM setting resource action.
var TerraformActionSelfHostedPAMSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-self-hosted-pam",
			ActionDescription: "The SIA PAM Self-Hosted resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsSelfHostedPam{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-self-hosted-pam",
		actions.ReadOperation:   "self-hosted-pam",
		actions.UpdateOperation: "set-self-hosted-pam",
	},
}

// TerraformActionRdpKerberosAuthModeSettingResource is a struct that defines the SIA RDP Kerberos Auth Mode setting resource action.
var TerraformActionRdpKerberosAuthModeSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-kerberos-auth-mode",
			ActionDescription: "The SIA RDP Kerberos auth mode resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpKerberosAuthMode{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-rdp-kerberos-auth-mode",
		actions.ReadOperation:   "rdp-kerberos-auth-mode",
		actions.UpdateOperation: "set-rdp-kerberos-auth-mode",
	},
}

// TerraformActionRdpTranscriptionSettingResource is a struct that defines the SIA RDP Transcription setting resource action.
var TerraformActionRdpTranscriptionSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-transcription",
			ActionDescription: "The SIA RDP transcription resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpTranscription{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-rdp-transcription",
		actions.ReadOperation:   "rdp-transcription",
		actions.UpdateOperation: "set-rdp-transcription",
	},
}

// TerraformActionSshRecordingSettingResource is a struct that defines the SIA SSH Recording setting resource action.
var TerraformActionSshRecordingSettingResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-ssh-recording",
			ActionDescription: "The SIA SSH recording resource.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsSshRecording{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "set-ssh-recording",
		actions.ReadOperation:   "ssh-recording",
		actions.UpdateOperation: "set-ssh-recording",
	},
}
