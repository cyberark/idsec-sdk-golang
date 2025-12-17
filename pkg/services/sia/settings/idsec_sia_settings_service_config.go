package settings

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	siasettingsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings/actions"
)

// ServiceConfig is the configuration for the IdsecSIASettingsService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-settings",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			siasettingsactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			siasettingsactions.TerraformActionSettingsResource,
			siasettingsactions.TerraformActionAdbMfaCachingSettingResource,
			siasettingsactions.TerraformActionCertificateValidationSettingResource,
			siasettingsactions.TerraformActionK8sMfaCachingSettingResource,
			siasettingsactions.TerraformActionRdpFileTransferSettingResource,
			siasettingsactions.TerraformActionRdpKeyboardLayoutSettingResource,
			siasettingsactions.TerraformActionRdpMfaCachingSettingResource,
			siasettingsactions.TerraformActionRdpTokenMfaCachingSettingResource,
			siasettingsactions.TerraformActionRdpRecordingSettingResource,
			siasettingsactions.TerraformActionSshMfaCachingSettingResource,
			siasettingsactions.TerraformActionSshCommandAuditSettingResource,
			siasettingsactions.TerraformActionStandingAccessSettingResource,
			siasettingsactions.TerraformActionLogonSequenceSettingResource,
			siasettingsactions.TerraformActionSelfHostedPAMSettingResource,
			siasettingsactions.TerraformActionRdpKerberosAuthModeSettingResource,
			siasettingsactions.TerraformActionRdpTranscriptionSettingResource,
			siasettingsactions.TerraformActionSshRecordingSettingResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			siasettingsactions.TerraformActionSettingsDataSource,
			siasettingsactions.TerraformActionAdbMfaCachingDataSource,
			siasettingsactions.TerraformActionCertificateValidationDataSource,
			siasettingsactions.TerraformActionK8sMfaCachingDataSource,
			siasettingsactions.TerraformActionRdpFileTransferDataSource,
			siasettingsactions.TerraformActionRdpKeyboardLayoutDataSource,
			siasettingsactions.TerraformActionRdpMfaCachingDataSource,
			siasettingsactions.TerraformActionRdpTokenMfaCachingDataSource,
			siasettingsactions.TerraformActionRdpRecordingDataSource,
			siasettingsactions.TerraformActionSshMfaCachingDataSource,
			siasettingsactions.TerraformActionSshCommandAuditDataSource,
			siasettingsactions.TerraformActionStandingAccessDataSource,
			siasettingsactions.TerraformActionLogonSequenceDataSource,
			siasettingsactions.TerraformActionSelfHostedPAMDataSource,
			siasettingsactions.TerraformActionRdpKerberosAuthModeDataSource,
			siasettingsactions.TerraformActionRdpTranscriptionDataSource,
			siasettingsactions.TerraformActionSshRecordingDataSource,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the SIA SSH CA service.
var ServiceGenerator = NewIdsecSIASettingsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
