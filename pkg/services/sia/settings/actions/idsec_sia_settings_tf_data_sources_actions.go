package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	settingsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings/models"
)

// TerraformActionSettingsDataSource is a struct that defines the SIA Settings data source action.
var TerraformActionSettingsDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-settings",
			ActionDescription: "SIA ListSettings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettings{},
	},
	DataSourceAction: "list-settings",
}

// TerraformActionAdbMfaCachingDataSource is a struct that defines the SIA ADB Mfa Caching setting data source action.
var TerraformActionAdbMfaCachingDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-adb-mfa-caching",
			ActionDescription: "SIA ADB MFA Caching Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsAdbMfaCaching{},
	},
	DataSourceAction: "adb-mfa-caching",
}

// TerraformActionCertificateValidationDataSource is a struct that defines the SIA Certificate Validation setting data source action.
var TerraformActionCertificateValidationDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-certificate-validation",
			ActionDescription: "SIA Certificate Validation Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsCertificateValidation{},
	},
	DataSourceAction: "certificate-validation",
}

// TerraformActionK8sMfaCachingDataSource is a struct that defines the SIA K8s Mfa Caching setting data source action.
var TerraformActionK8sMfaCachingDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-k8s-mfa-caching",
			ActionDescription: "SIA K8s MFA Caching Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsK8sMfaCaching{},
	},
	DataSourceAction: "k8s-mfa-caching",
}

// TerraformActionRdpFileTransferDataSource is a struct that defines the SIA RDP File Transfer setting data source action.
var TerraformActionRdpFileTransferDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-file-transfer",
			ActionDescription: "SIA RDP File Transfer Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpFileTransfer{},
	},
	DataSourceAction: "rdp-file-transfer",
}

// TerraformActionRdpKeyboardLayoutDataSource is a struct that defines the SIA RDP Keyboard Layout setting data source action.
var TerraformActionRdpKeyboardLayoutDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-keyboard-layout",
			ActionDescription: "SIA RDP Keyboard Layout Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpKeyboardLayout{},
	},
	DataSourceAction: "rdp-keyboard-layout",
}

// TerraformActionRdpMfaCachingDataSource is a struct that defines the SIA RDP Mfa Caching setting data source action.
var TerraformActionRdpMfaCachingDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-mfa-caching",
			ActionDescription: "SIA RDP MFA Caching Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpMfaCaching{},
	},
	DataSourceAction: "rdp-mfa-caching",
}

// TerraformActionRdpTokenMfaCachingDataSource is a struct that defines the SIA RDP Token Mfa Caching setting data source action.
var TerraformActionRdpTokenMfaCachingDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-token-mfa-caching",
			ActionDescription: "SIA RDP Token MFA Caching Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpTokenMfaCaching{},
	},
	DataSourceAction: "rdp-token-mfa-caching",
}

// TerraformActionRdpRecordingDataSource is a struct that defines the SIA RDP Recording setting data source action.
var TerraformActionRdpRecordingDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-recording",
			ActionDescription: "SIA RDP Recording Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpRecording{},
	},
	DataSourceAction: "rdp-recording",
}

// TerraformActionSshMfaCachingDataSource defines the SIA SSH Mfa Caching setting data source action.
var TerraformActionSshMfaCachingDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-ssh-mfa-caching",
			ActionDescription: "SIA SSH MFA Caching Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsSshMfaCaching{},
	},
	DataSourceAction: "ssh-mfa-caching",
}

// TerraformActionSshCommandAuditDataSource is a struct that defines the SIA SSH Command Audit setting data source action.
var TerraformActionSshCommandAuditDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-ssh-command-audit",
			ActionDescription: "SIA SSH Command Audit Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsSshCommandAudit{},
	},
	DataSourceAction: "ssh-command-audit",
}

// TerraformActionStandingAccessDataSource is a struct that defines the SIA Standing Access setting data source action.
var TerraformActionStandingAccessDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-standing-access",
			ActionDescription: "SIA Standing Access Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsStandingAccess{},
	},
	DataSourceAction: "standing-access",
}

// TerraformActionLogonSequenceDataSource is a struct that defines the SIA Logon Sequence setting data source action.
var TerraformActionLogonSequenceDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-logon-sequence",
			ActionDescription: "SIA Logon Sequence Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsLogonSequence{},
	},
	DataSourceAction: "logon-sequence",
}

// TerraformActionSelfHostedPAMDataSource is a struct that defines the SIA Self-Hosted PAM setting data source action.
var TerraformActionSelfHostedPAMDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-self-hosted-pam",
			ActionDescription: "SIA Self-Hosted PAM Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsSelfHostedPam{},
	},
	DataSourceAction: "self-hosted-pam",
}

// TerraformActionRdpKerberosAuthModeDataSource is a struct that defines the SIA RDP Kerberos Auth Mode setting data source action.
var TerraformActionRdpKerberosAuthModeDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-kerberos-auth-mode",
			ActionDescription: "SIA RDP Kerberos Auth Mode Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpKerberosAuthMode{},
	},
	DataSourceAction: "rdp-kerberos-auth-mode",
}

// TerraformActionRdpTranscriptionDataSource is a struct that defines the SIA RDP Transcription setting data source action.
var TerraformActionRdpTranscriptionDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-rdp-transcription",
			ActionDescription: "SIA RDP Transcription Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsRdpTranscription{},
	},
	DataSourceAction: "rdp-transcription",
}

// TerraformActionSshRecordingDataSource is a struct that defines the SIA SSH Recording setting data source action.
var TerraformActionSshRecordingDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-settings-ssh-recording",
			ActionDescription: "SIA SSH Recording Settings Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &settingsmodels.IdsecSIASettingsSshRecording{},
	},
	DataSourceAction: "ssh-recording",
}
