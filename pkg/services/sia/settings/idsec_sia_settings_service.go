package settings

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	settingsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings/models"
)

const (
	settingsURL = "/api/settings"
	settingURL  = "/api/settings/%s"
)

// IdsecSIASettingsService is a struct that implements the IdsecService interface and provides functionality for settings of SIA.
type IdsecSIASettingsService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient

	// For testing purposes
	doGet   func(ctx context.Context, path string, params interface{}) (*http.Response, error)
	doPut   func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	doPatch func(ctx context.Context, path string, body interface{}) (*http.Response, error)
}

// NewIdsecSIASettingsService creates a new instance of IdsecSIASettingsService with the provided authenticators.
func NewIdsecSIASettingsService(authenticators ...auth.IdsecAuth) (*IdsecSIASettingsService, error) {
	siaSettingsService := &IdsecSIASettingsService{}
	var sshCaServiceInterface services.IdsecService = siaSettingsService
	baseService, err := services.NewIdsecBaseService(sshCaServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", siaSettingsService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	siaSettingsService.client = client
	siaSettingsService.ispAuth = ispAuth
	siaSettingsService.IdsecBaseService = baseService
	return siaSettingsService, nil
}

func (s *IdsecSIASettingsService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSIASettingsService) getOperation() func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	if s.doGet != nil {
		return s.doGet
	}
	return s.client.Get
}

func (s *IdsecSIASettingsService) putOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPut != nil {
		return s.doPut
	}
	return s.client.Put
}

func (s *IdsecSIASettingsService) patchOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPatch != nil {
		return s.doPatch
	}
	return s.client.Patch
}

func (s *IdsecSIASettingsService) setting(featureName string) (map[string]interface{}, error) {
	s.Logger.Info("Retrieving setting [%s]", featureName)
	response, err := s.getOperation()(context.Background(), fmt.Sprintf(settingURL, featureName), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve setting - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	settingJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	settingJSONMap := settingJSON.(map[string]interface{})
	if settingConf, ok := settingJSONMap["feature_conf"]; ok {
		return settingConf.(map[string]interface{}), nil
	}
	return nil, fmt.Errorf("feature_conf not found in setting response")
}

func (s *IdsecSIASettingsService) setSetting(featureName string, setting map[string]interface{}) error {
	s.Logger.Info("Setting setting [%s]", featureName)
	if len(setting) == 0 {
		return nil
	}
	settingBody, err := common.SerializeJSONCamel(setting)
	if err != nil {
		return err
	}
	response, err := s.putOperation()(context.Background(), fmt.Sprintf(settingURL, featureName), settingBody)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to set setting - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ListSettings retrieves the Idsec SIA settings.
//
// Returns the current Idsec SIA settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) ListSettings() (*settingsmodels.IdsecSIASettings, error) {
	s.Logger.Info("Retrieving settings")
	response, err := s.getOperation()(context.Background(), settingsURL, nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve settings - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	settingsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var settings settingsmodels.IdsecSIASettings
	err = mapstructure.Decode(settingsJSON, &settings)
	if err != nil {
		return nil, err
	}
	// Handle special cases, k8s and ssh
	if k8sSettings, ok := settingsJSON.(map[string]interface{})["k_8_s_mfa_caching"]; ok {
		var k8sMfaCaching settingsmodels.IdsecSIASettingsK8sMfaCaching
		err = mapstructure.Decode(k8sSettings, &k8sMfaCaching)
		if err != nil {
			return nil, err
		}
		settings.K8sMfaCaching = &k8sMfaCaching
	}
	if sshSettings, ok := settingsJSON.(map[string]interface{})["mfa_caching"]; ok {
		var sshMfaCaching settingsmodels.IdsecSIASettingsSshMfaCaching
		err = mapstructure.Decode(sshSettings, &sshMfaCaching)
		if err != nil {
			return nil, err
		}
		settings.SshMfaCaching = &sshMfaCaching
	}
	return &settings, nil
}

// SetSettings sets the Idsec SIA settings.
//
// Parameters:
//   - settings: The Idsec SIA settings to be applied.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetSettings(settings *settingsmodels.IdsecSIASettings) (*settingsmodels.IdsecSIASettings, error) {
	settingsJSON, err := common.SerializeJSONCamel(settings)
	if err != nil {
		return nil, err
	}
	s.Logger.Info("Setting settings")
	response, err := s.patchOperation()(context.Background(), settingsURL, settingsJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to set settings - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.ListSettings()
}

// AdbMfaCaching retrieves the ADB MFA Caching settings.
//
// Returns the current ADB MFA Caching settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) AdbMfaCaching() (*settingsmodels.IdsecSIASettingsAdbMfaCaching, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameADBMfaCaching)
	if err != nil {
		return nil, err
	}
	var adbMfaCaching settingsmodels.IdsecSIASettingsAdbMfaCaching
	err = mapstructure.Decode(settingJSON, &adbMfaCaching)
	if err != nil {
		return nil, err
	}
	return &adbMfaCaching, nil
}

// SetAdbMfaCaching sets the ADB MFA Caching settings.
//
// Parameters:
//   - adbMfaCaching: The settings to apply for ADB MFA Caching.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetAdbMfaCaching(adbMfaCaching *settingsmodels.IdsecSIASettingsAdbMfaCaching) (*settingsmodels.IdsecSIASettingsAdbMfaCaching, error) {
	settingJSON, err := common.SerializeJSONCamel(adbMfaCaching)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameADBMfaCaching, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.AdbMfaCaching()
}

// CertificateValidation retrieves the Certificate Validation settings.
//
// Returns the current Certificate Validation settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) CertificateValidation() (*settingsmodels.IdsecSIASettingsCertificateValidation, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameCertificateValidation)
	if err != nil {
		return nil, err
	}
	var certificateValidation settingsmodels.IdsecSIASettingsCertificateValidation
	err = mapstructure.Decode(settingJSON, &certificateValidation)
	if err != nil {
		return nil, err
	}
	return &certificateValidation, nil
}

// SetCertificateValidation sets the Certificate Validation settings.
//
// Parameters:
//   - certificateValidation: The settings to apply for Certificate Validation.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetCertificateValidation(certificateValidation *settingsmodels.IdsecSIASettingsCertificateValidation) (*settingsmodels.IdsecSIASettingsCertificateValidation, error) {
	settingJSON, err := common.SerializeJSONCamel(certificateValidation)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameCertificateValidation, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.CertificateValidation()
}

// K8sMfaCaching retrieves the K8S MFA Caching settings.
//
// Returns the current K8S MFA Caching settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) K8sMfaCaching() (*settingsmodels.IdsecSIASettingsK8sMfaCaching, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameK8SMfaCaching)
	if err != nil {
		return nil, err
	}
	var k8sMfaCaching settingsmodels.IdsecSIASettingsK8sMfaCaching
	err = mapstructure.Decode(settingJSON, &k8sMfaCaching)
	if err != nil {
		return nil, err
	}
	return &k8sMfaCaching, nil
}

// SetK8sMfaCaching sets the K8S MFA Caching settings.
//
// Parameters:
//   - k8sMfaCaching: The settings to apply for K8S MFA Caching.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetK8sMfaCaching(k8sMfaCaching *settingsmodels.IdsecSIASettingsK8sMfaCaching) (*settingsmodels.IdsecSIASettingsK8sMfaCaching, error) {
	settingJSON, err := common.SerializeJSONCamel(k8sMfaCaching)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameK8SMfaCaching, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.K8sMfaCaching()
}

// RdpFileTransfer retrieves the RDP File Transfer settings.
//
// Returns the current RDP File Transfer settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) RdpFileTransfer() (*settingsmodels.IdsecSIASettingsRdpFileTransfer, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameRDPFileTransfer)
	if err != nil {
		return nil, err
	}
	var rdpFileTransfer settingsmodels.IdsecSIASettingsRdpFileTransfer
	err = mapstructure.Decode(settingJSON, &rdpFileTransfer)
	if err != nil {
		return nil, err
	}
	return &rdpFileTransfer, nil
}

// SetRdpFileTransfer sets the RDP File Transfer settings.
//
// Parameters:
//   - rdpFileTransfer: The settings to apply for RDP File Transfer.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetRdpFileTransfer(rdpFileTransfer *settingsmodels.IdsecSIASettingsRdpFileTransfer) (*settingsmodels.IdsecSIASettingsRdpFileTransfer, error) {
	settingJSON, err := common.SerializeJSONCamel(rdpFileTransfer)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameRDPFileTransfer, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.RdpFileTransfer()
}

// RdpKeyboardLayout retrieves the RDP Keyboard Layout settings.
//
// Returns the current RDP Keyboard Layout settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) RdpKeyboardLayout() (*settingsmodels.IdsecSIASettingsRdpKeyboardLayout, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameRDPKeyboardLayout)
	if err != nil {
		return nil, err
	}
	var rdpKeyboardLayout settingsmodels.IdsecSIASettingsRdpKeyboardLayout
	err = mapstructure.Decode(settingJSON, &rdpKeyboardLayout)
	if err != nil {
		return nil, err
	}
	return &rdpKeyboardLayout, nil
}

// SetRDPKeyboardLayout sets the RDP Keyboard Layout settings.
//
// Parameters:
//   - rdpKeyboardLayout: The settings to apply for RDP Keyboard Layout.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetRDPKeyboardLayout(rdpKeyboardLayout *settingsmodels.IdsecSIASettingsRdpKeyboardLayout) (*settingsmodels.IdsecSIASettingsRdpKeyboardLayout, error) {
	settingJSON, err := common.SerializeJSONCamel(rdpKeyboardLayout)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameRDPKeyboardLayout, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.RdpKeyboardLayout()
}

// RdpMfaCaching retrieves the RDP MFA Caching settings.
//
// Returns the current RDP MFA Caching settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) RdpMfaCaching() (*settingsmodels.IdsecSIASettingsRdpMfaCaching, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameRDPMfaCaching)
	if err != nil {
		return nil, err
	}
	var rdpMfaCaching settingsmodels.IdsecSIASettingsRdpMfaCaching
	err = mapstructure.Decode(settingJSON, &rdpMfaCaching)
	if err != nil {
		return nil, err
	}
	return &rdpMfaCaching, nil
}

// SetRdpMfaCaching sets the RDP MFA Caching settings.
//
// Parameters:
//   - rdpMfaCaching: The settings to apply for RDP MFA Caching.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetRdpMfaCaching(rdpMfaCaching *settingsmodels.IdsecSIASettingsRdpMfaCaching) (*settingsmodels.IdsecSIASettingsRdpMfaCaching, error) {
	settingJSON, err := common.SerializeJSONCamel(rdpMfaCaching)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameRDPMfaCaching, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.RdpMfaCaching()
}

// RDPTokenMfaCaching retrieves the RDP Token MFA Caching settings.
//
// Returns the current RDP Token MFA Caching settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) RDPTokenMfaCaching() (*settingsmodels.IdsecSIASettingsRdpTokenMfaCaching, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameRDPTokenMfaCaching)
	if err != nil {
		return nil, err
	}
	var rdpTokenMfaCaching settingsmodels.IdsecSIASettingsRdpTokenMfaCaching
	err = mapstructure.Decode(settingJSON, &rdpTokenMfaCaching)
	if err != nil {
		return nil, err
	}
	return &rdpTokenMfaCaching, nil
}

// SetRdpTokenMfaCaching sets the RDP Token MFA Caching settings.
//
// Parameters:
//   - rdpTokenMfaCaching: The settings to apply for RDP Token MFA Caching.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetRdpTokenMfaCaching(rdpTokenMfaCaching *settingsmodels.IdsecSIASettingsRdpTokenMfaCaching) (*settingsmodels.IdsecSIASettingsRdpTokenMfaCaching, error) {
	settingJSON, err := common.SerializeJSONCamel(rdpTokenMfaCaching)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameRDPTokenMfaCaching, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.RDPTokenMfaCaching()
}

// RdpRecording retrieves the RDP Recording settings.
//
// Returns the current RDP Recording settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) RdpRecording() (*settingsmodels.IdsecSIASettingsRdpRecording, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameRDPRecording)
	if err != nil {
		return nil, err
	}
	var rdpRecording settingsmodels.IdsecSIASettingsRdpRecording
	err = mapstructure.Decode(settingJSON, &rdpRecording)
	if err != nil {
		return nil, err
	}
	return &rdpRecording, nil
}

// SetRdpRecording sets the RDP Recording settings.
//
// Parameters:
//   - rdpRecording: The settings to apply for RDP Recording.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetRdpRecording(rdpRecording *settingsmodels.IdsecSIASettingsRdpRecording) (*settingsmodels.IdsecSIASettingsRdpRecording, error) {
	settingJSON, err := common.SerializeJSONCamel(rdpRecording)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameRDPRecording, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.RdpRecording()
}

// SshMfaCaching retrieves the SSH MFA Caching settings.
//
// Returns the current SSH MFA Caching settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) SshMfaCaching() (*settingsmodels.IdsecSIASettingsSshMfaCaching, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameSSHMfaCaching)
	if err != nil {
		return nil, err
	}
	var sshMfaCaching settingsmodels.IdsecSIASettingsSshMfaCaching
	err = mapstructure.Decode(settingJSON, &sshMfaCaching)
	if err != nil {
		return nil, err
	}
	return &sshMfaCaching, nil
}

// SetSshMfaCaching sets the SSH MFA Caching settings.
//
// Parameters:
//   - sshMfaCaching: The settings to apply for SSH MFA Caching.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetSshMfaCaching(sshMfaCaching *settingsmodels.IdsecSIASettingsSshMfaCaching) (*settingsmodels.IdsecSIASettingsSshMfaCaching, error) {
	settingJSON, err := common.SerializeJSONCamel(sshMfaCaching)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameSSHMfaCaching, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.SshMfaCaching()
}

// SshCommandAudit retrieves the SSH Command Audit settings.
//
// Returns the current SSH Command Audit settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) SshCommandAudit() (*settingsmodels.IdsecSIASettingsSshCommandAudit, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameSSHCommandAudit)
	if err != nil {
		return nil, err
	}
	var sshCommandAudit settingsmodels.IdsecSIASettingsSshCommandAudit
	err = mapstructure.Decode(settingJSON, &sshCommandAudit)
	if err != nil {
		return nil, err
	}
	return &sshCommandAudit, nil
}

// SetSshCommandAudit sets the SSH Command Audit settings.
//
// Parameters:
//   - sshCommandAudit: The settings to apply for SSH Command Audit.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetSshCommandAudit(sshCommandAudit *settingsmodels.IdsecSIASettingsSshCommandAudit) (*settingsmodels.IdsecSIASettingsSshCommandAudit, error) {
	settingJSON, err := common.SerializeJSONCamel(sshCommandAudit)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameSSHCommandAudit, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.SshCommandAudit()
}

// StandingAccess retrieves the Standing Access settings.
//
// Returns the current Standing Access settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) StandingAccess() (*settingsmodels.IdsecSIASettingsStandingAccess, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameStandingAccess)
	if err != nil {
		return nil, err
	}
	var standingAccess settingsmodels.IdsecSIASettingsStandingAccess
	err = mapstructure.Decode(settingJSON, &standingAccess)
	if err != nil {
		return nil, err
	}
	return &standingAccess, nil
}

// SetStandingAccess sets the Standing Access settings.
//
// Parameters:
//   - standingAccess: The settings to apply for Standing Access.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetStandingAccess(standingAccess *settingsmodels.IdsecSIASettingsStandingAccess) (*settingsmodels.IdsecSIASettingsStandingAccess, error) {
	settingJSON, err := common.SerializeJSONCamel(standingAccess)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameStandingAccess, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.StandingAccess()
}

// LogonSequence retrieves the Logon Sequence settings.
//
// Returns the current Logon Sequence settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) LogonSequence() (*settingsmodels.IdsecSIASettingsLogonSequence, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameLogonSequence)
	if err != nil {
		return nil, err
	}
	var logonSequence settingsmodels.IdsecSIASettingsLogonSequence
	err = mapstructure.Decode(settingJSON, &logonSequence)
	if err != nil {
		return nil, err
	}
	return &logonSequence, nil
}

// SetLogonSequence sets the Logon Sequence settings.
//
// Parameters:
//   - logonSequence: The settings to apply for Logon Sequence.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetLogonSequence(logonSequence *settingsmodels.IdsecSIASettingsLogonSequence) (*settingsmodels.IdsecSIASettingsLogonSequence, error) {
	settingJSON, err := common.SerializeJSONCamel(logonSequence)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameLogonSequence, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.LogonSequence()
}

// SelfHostedPam retrieves the Self-Hosted PAM settings.
//
// Returns the current Self-Hosted PAM settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) SelfHostedPam() (*settingsmodels.IdsecSIASettingsSelfHostedPam, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameSelfHostedPAM)
	if err != nil {
		return nil, err
	}
	var selfHostedPAM settingsmodels.IdsecSIASettingsSelfHostedPam
	err = mapstructure.Decode(settingJSON, &selfHostedPAM)
	if err != nil {
		return nil, err
	}
	return &selfHostedPAM, nil
}

// SetSelfHostedPam sets the Self-Hosted PAM settings.
//
// Parameters:
//   - selfHostedPAM: The settings to apply for Self-Hosted PAM.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetSelfHostedPam(selfHostedPAM *settingsmodels.IdsecSIASettingsSelfHostedPam) (*settingsmodels.IdsecSIASettingsSelfHostedPam, error) {
	settingJSON, err := common.SerializeJSONCamel(selfHostedPAM)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameSelfHostedPAM, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.SelfHostedPam()
}

// RdpKerberosAuthMode retrieves the RDP Kerberos Auth Mode settings.
//
// Returns the current RDP Kerberos Auth Mode settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) RdpKerberosAuthMode() (*settingsmodels.IdsecSIASettingsRdpKerberosAuthMode, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameRDPKerberosAuthMode)
	if err != nil {
		return nil, err
	}
	var rdpKerberosAuthMode settingsmodels.IdsecSIASettingsRdpKerberosAuthMode
	err = mapstructure.Decode(settingJSON, &rdpKerberosAuthMode)
	if err != nil {
		return nil, err
	}
	return &rdpKerberosAuthMode, nil
}

// SetRdpKerberosAuthMode sets the RDP Kerberos Auth Mode settings.
//
// Parameters:
//   - rdpKerberosAuthMode: The settings to apply for RDP Kerberos Auth Mode.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetRdpKerberosAuthMode(rdpKerberosAuthMode *settingsmodels.IdsecSIASettingsRdpKerberosAuthMode) (*settingsmodels.IdsecSIASettingsRdpKerberosAuthMode, error) {
	settingJSON, err := common.SerializeJSONCamel(rdpKerberosAuthMode)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameRDPKerberosAuthMode, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.RdpKerberosAuthMode()
}

// RdpTranscription retrieves the RDP Transcription settings.
//
// Returns the current RDP Transcription settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) RdpTranscription() (*settingsmodels.IdsecSIASettingsRdpTranscription, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameRDPTranscription)
	if err != nil {
		return nil, err
	}
	var rdpTranscription settingsmodels.IdsecSIASettingsRdpTranscription
	err = mapstructure.Decode(settingJSON, &rdpTranscription)
	if err != nil {
		return nil, err
	}
	return &rdpTranscription, nil
}

// SetRdpTranscription sets the RDP Transcription settings.
//
// Parameters:
//   - rdpTranscription: The settings to apply for RDP Transcription.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetRdpTranscription(rdpTranscription *settingsmodels.IdsecSIASettingsRdpTranscription) (*settingsmodels.IdsecSIASettingsRdpTranscription, error) {
	settingJSON, err := common.SerializeJSONCamel(rdpTranscription)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameRDPTranscription, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.RdpTranscription()
}

// SshRecording retrieves the SSH Recording settings.
//
// Returns the current SSH Recording settings or an error if retrieval fails.
func (s *IdsecSIASettingsService) SshRecording() (*settingsmodels.IdsecSIASettingsSshRecording, error) {
	settingJSON, err := s.setting(settingsmodels.IdsecSIASettingsFeatureNameSSHRecording)
	if err != nil {
		return nil, err
	}
	var sshRecording settingsmodels.IdsecSIASettingsSshRecording
	err = mapstructure.Decode(settingJSON, &sshRecording)
	if err != nil {
		return nil, err
	}
	return &sshRecording, nil
}

// SetSshRecording sets the SSH Recording settings.
//
// Parameters:
//   - sshRecording: The settings to apply for SSH Recording.
//
// Returns an error if the operation fails.
func (s *IdsecSIASettingsService) SetSshRecording(sshRecording *settingsmodels.IdsecSIASettingsSshRecording) (*settingsmodels.IdsecSIASettingsSshRecording, error) {
	settingJSON, err := common.SerializeJSONCamel(sshRecording)
	if err != nil {
		return nil, err
	}
	err = s.setSetting(settingsmodels.IdsecSIASettingsFeatureNameSSHRecording, settingJSON)
	if err != nil {
		return nil, err
	}
	return s.SshRecording()
}

// ServiceConfig returns the service configuration for the IdsecSIASettingsService.
func (s *IdsecSIASettingsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
