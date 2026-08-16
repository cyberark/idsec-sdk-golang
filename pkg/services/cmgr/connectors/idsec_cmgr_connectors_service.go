package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections/ssh"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections/winrm"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	connectionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections/connectiondata"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	connectorsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/connectors/models"
)

const (
	setupScriptURL = "api/setup-script"
	connectorURL   = "api/connectors/%s"

	linuxServiceName   = "idira-management-agent"
	windowsServiceName = "CyberArkManagementAgent"

	connectorInstallRetryCount = 10
	connectorInstallRetryTick  = 10.0 * time.Second
	connectorReadyRetryCount   = 10
	connectorRetryTick         = 3.0 * time.Second

	defaultWindowsInstallPath = `C:\Program Files`
)

var connectorInstallRetryErrors = []string{
	"invalid content type",
}

// IdsecCmgrConnectorsService is the service for installing management agent connectors.
type IdsecCmgrConnectorsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecCmgrConnectorsService creates a new instance of IdsecCmgrConnectorsService.
func NewIdsecCmgrConnectorsService(authenticators ...auth.IdsecAuth) (*IdsecCmgrConnectorsService, error) {
	connectorsService := &IdsecCmgrConnectorsService{}
	var connectorsServiceInterface services.IdsecService = connectorsService
	baseService, err := services.NewIdsecBaseService(connectorsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "connectormanagement", ".", "", connectorsService.refreshAuth)
	if err != nil {
		return nil, err
	}

	connectorsService.IdsecBaseService = baseService
	connectorsService.IdsecISPBaseService = ispBaseService
	return connectorsService, nil
}

func (s *IdsecCmgrConnectorsService) refreshAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func linuxInstallDir(installationPath string) string {
	return installationPath + "/opt/idira/management-agent"
}

func windowsInstallDir(installationPath string) string {
	if installationPath == "" {
		installationPath = defaultWindowsInstallPath
	}
	return installationPath + `\CyberArk\Management Agent`
}

func buildCmdSet(installationPath string) map[string]map[string]string {
	linuxDir := linuxInstallDir(installationPath)
	windowsDir := windowsInstallDir(installationPath)

	unixStop := fmt.Sprintf("sudo systemctl stop %s", linuxServiceName)
	unixRemoveService := fmt.Sprintf(
		"sudo rm -f /etc/systemd/system/%[1]s.service && sudo systemctl daemon-reload && sudo systemctl reset-failed",
		linuxServiceName,
	)
	unixRemoveFiles := fmt.Sprintf("sudo rm -rf %q", linuxDir)
	unixActive := fmt.Sprintf("sudo systemctl is-active --quiet %s", linuxServiceName)
	unixReadConfig := fmt.Sprintf("sudo cat %q", linuxDir+"/client.id.json")

	winStop := fmt.Sprintf("Stop-Service -Name %q", windowsServiceName)
	winRemoveService := fmt.Sprintf(
		`$service = Get-WmiObject -Class Win32_Service -Filter "Name='%s'"; $service.delete()`,
		windowsServiceName,
	)
	winRemoveFiles := fmt.Sprintf(`Remove-Item -LiteralPath "%s" -Force -Recurse`, windowsDir)
	winActive := fmt.Sprintf(
		`$result = Get-Service -Name "%s"; if ($result.Status -ne 'Running') { return 1 }`,
		windowsServiceName,
	)
	winReadConfig := fmt.Sprintf(`Get-Content -Path "%s\client.id.json"`, windowsDir)

	return map[string]map[string]string{
		commonmodels.OSTypeLinux: {
			"stopService":   unixStop,
			"removeService": unixRemoveService,
			"removeFiles":   unixRemoveFiles,
			"isActive":      unixActive,
			"readConfig":    unixReadConfig,
		},
		commonmodels.OSTypeWindows: {
			"stopService":   winStop,
			"removeService": winRemoveService,
			"removeFiles":   winRemoveFiles,
			"isActive":      winActive,
			"readConfig":    winReadConfig,
		},
	}
}

func (s *IdsecCmgrConnectorsService) createWinRMConnection(
	targetMachine string,
	username string,
	password string,
	retryCount int,
	retryDelay int,
	winrmProtocol string,
) (connections.IdsecConnection, error) {
	protocol := winrm.WinRMHTTPSPort
	if strings.ToLower(winrmProtocol) == "http" {
		protocol = winrm.WinRMHTTPPort
	}
	connection := winrm.NewIdsecWinRMConnection()
	connectionDetails := &connectionsmodels.IdsecConnectionDetails{
		Address:        targetMachine,
		Port:           protocol,
		ConnectionType: connectionsmodels.WinRM,
		Credentials: &connectionsmodels.IdsecConnectionCredentials{
			User:     username,
			Password: password,
		},
		ConnectionData: &connectiondata.IdsecWinRMConnectionData{
			CertificatePath:  "",
			TrustCertificate: true,
			Protocol:         winrmProtocol,
		},
		ConnectionRetries: retryCount,
		RetryTickPeriod:   retryDelay,
	}
	if err := connection.Connect(connectionDetails); err != nil {
		return nil, fmt.Errorf("failed to connect via WinRM: %w", err)
	}
	return connection, nil
}

func (s *IdsecCmgrConnectorsService) createSSHConnection(
	targetMachine string,
	username string,
	password string,
	privateKeyPath string,
	privateKeyContents string,
	retryCount int,
	retryDelay int,
) (connections.IdsecConnection, error) {
	connection := ssh.NewIdsecSSHConnection()
	connectionDetails := &connectionsmodels.IdsecConnectionDetails{
		Address:        targetMachine,
		Port:           ssh.SSHPort,
		ConnectionType: connectionsmodels.SSH,
		Credentials: &connectionsmodels.IdsecConnectionCredentials{
			User:               username,
			Password:           password,
			PrivateKeyFilepath: privateKeyPath,
			PrivateKeyContents: privateKeyContents,
		},
		ConnectionData:    &connectiondata.IdsecSSHConnectionData{},
		ConnectionRetries: retryCount,
		RetryTickPeriod:   retryDelay,
	}
	if err := connection.Connect(connectionDetails); err != nil {
		return nil, fmt.Errorf("failed to connect via SSH: %w", err)
	}
	return connection, nil
}

func (s *IdsecCmgrConnectorsService) createConnection(
	osType string,
	targetMachine string,
	username string,
	password string,
	privateKeyPath string,
	privateKeyContents string,
	retryCount int,
	retryDelay int,
	winrmProtocol string,
) (connections.IdsecConnection, error) {
	var (
		connection connections.IdsecConnection
		err        error
	)
	if osType == commonmodels.OSTypeWindows {
		connection, err = s.createWinRMConnection(targetMachine, username, password, retryCount, retryDelay, winrmProtocol)
	} else {
		connection, err = s.createSSHConnection(targetMachine, username, password, privateKeyPath, privateKeyContents, retryCount, retryDelay)
	}
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func (s *IdsecCmgrConnectorsService) cleanupConnectorOnMachine(connection connections.IdsecConnection, cmdSet map[string]string) {
	_, err := connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["stopService"],
	})
	if err != nil {
		s.Logger.Debug("failed to stop connector service (may already be absent): %v", err)
	}

	_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["removeService"],
	})
	if err != nil {
		s.Logger.Debug("failed to remove connector service (may already be absent): %v", err)
	}

	_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["removeFiles"],
	})
	if err != nil {
		s.Logger.Debug("failed to remove connector files (may already be absent): %v", err)
	}
}

func (s *IdsecCmgrConnectorsService) installConnectorOnMachine(
	installScript string,
	osType string,
	installationPath string,
	targetMachine string,
	username string,
	password string,
	privateKeyPath string,
	privateKeyContents string,
	retryCount int,
	retryDelay int,
	winrmProtocol string,
) (*connectorsmodels.IdsecCmgrConnectorID, error) {
	connection, err := s.createConnection(
		osType,
		targetMachine,
		username,
		password,
		privateKeyPath,
		privateKeyContents,
		retryCount,
		retryDelay,
		winrmProtocol,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	defer func(connection connections.IdsecConnection) {
		err := connection.Disconnect()
		if err != nil {
			s.Logger.Warning("failed to disconnect: %v", err)
		}
	}(connection)

	cmdSet := buildCmdSet(installationPath)[osType]

	s.cleanupConnectorOnMachine(connection, cmdSet)

	if osType == commonmodels.OSTypeWindows {
		_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
			Command:          installScript,
			ExtraCommandData: map[string]interface{}{"force_command_split": true},
			RetryCount:       connectorInstallRetryCount,
			RetryDelay:       int(connectorInstallRetryTick.Seconds()),
			RetryOnErrors:    connectorInstallRetryErrors,
		})
	} else {
		_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
			Command: "export TERM=xterm; " + installScript,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to install connector: %w", err)
	}

	currRetry := connectorReadyRetryCount
	for {
		_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
			Command: cmdSet["isActive"],
		})
		if err == nil {
			break
		}
		if currRetry > 0 {
			currRetry--
			time.Sleep(connectorRetryTick)
			continue
		}
		return nil, fmt.Errorf("failed to check if connector is active: %w", err)
	}

	var result *connectionsmodels.IdsecConnectionResult
	currReadRetry := connectorReadyRetryCount
	// retry until the connector config is ready
	for {
		result, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
			Command: cmdSet["readConfig"],
		})
		if err == nil {
			break
		}
		if currReadRetry > 0 {
			s.Logger.Debug("client.id.json not ready yet, retrying in %v: %v", connectorRetryTick, err)
			currReadRetry--
			time.Sleep(connectorRetryTick)
			continue
		}
		return nil, fmt.Errorf("failed to read connector config: %w", err)
	}

	var connectorConfig map[string]interface{}
	if err := json.Unmarshal([]byte(result.Stdout), &connectorConfig); err != nil {
		return nil, fmt.Errorf("failed to parse connector config: %w", err)
	}
	thingID, ok := connectorConfig["thing_id"].(string)
	if !ok {
		return nil, fmt.Errorf("connector ID (thing_id) not found in config")
	}
	return &connectorsmodels.IdsecCmgrConnectorID{ConnectorID: thingID}, nil
}

// SetupScript retrieves the installation setup script for a management agent connector.
func (s *IdsecCmgrConnectorsService) SetupScript(req *connectorsmodels.IdsecCmgrGetSetupScript) (*connectorsmodels.IdsecCmgrSetupScript, error) {
	s.Logger.Info("Retrieving management agent connector setup script")
	var reqJSON map[string]interface{}

	err := mapstructure.Decode(req, &reqJSON)
	if err != nil {
		return nil, err
	}

	response, err := s.ISPClient().Post(context.Background(), setupScriptURL, reqJSON)
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
		return nil, fmt.Errorf("failed to retrieve connector setup script - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	setupScriptJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var setupScript connectorsmodels.IdsecCmgrSetupScript
	err = mapstructure.Decode(setupScriptJSON, &setupScript)
	if err != nil {
		return nil, err
	}
	return &setupScript, nil
}

// Get retrieves a specific connector by its ID from the connector management service.
func (s *IdsecCmgrConnectorsService) Get(req *connectorsmodels.IdsecCmgrGet) (*connectorsmodels.IdsecCmgrConnector, error) {
	s.Logger.Info("Retrieving connector [%s]", req.ConnectorID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(connectorURL, req.ConnectorID), nil)
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
		return nil, fmt.Errorf("failed to retrieve connector - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	connectorJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	connectorJSONMap := connectorJSON.(map[string]interface{})

	var connector connectorsmodels.IdsecCmgrConnector
	err = mapstructure.Decode(connectorJSONMap, &connector)
	if err != nil {
		return nil, err
	}
	return &connector, nil
}

// Install installs a management agent connector on the target machine.
func (s *IdsecCmgrConnectorsService) Install(req *connectorsmodels.IdsecCmgrInstall) (*connectorsmodels.IdsecCmgrConnectorID, error) {
	s.Logger.Info(
		"Installing management agent connector on machine [%s] of type [%s]",
		req.TargetMachine,
		req.ConnectorOS,
	)
	setupScript, err := s.SetupScript(&connectorsmodels.IdsecCmgrGetSetupScript{
		OsType:           req.ConnectorOS,
		ConnectorPoolID:  req.ConnectorPoolID,
		InstallationPath: req.InstallationPath,
		Version:          req.Version,
		ProxyDetails:     req.ProxyDetails,
		TenantInfo:       req.TenantInfo,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve connector setup script: %w", err)
	}
	return s.installConnectorOnMachine(
		setupScript.Script,
		req.ConnectorOS,
		req.InstallationPath,
		req.TargetMachine,
		req.Username,
		req.Password,
		strings.TrimSuffix(common.ExpandFolder(req.PrivateKeyPath), "/"),
		req.PrivateKeyContents,
		req.RetryCount,
		req.RetryDelay,
		req.WinRMProtocol,
	)
}

func (s *IdsecCmgrConnectorsService) uninstallConnectorOnMachine(
	osType string,
	installationPath string,
	targetMachine string,
	username string,
	password string,
	privateKeyPath string,
	privateKeyContents string,
	retryCount int,
	retryDelay int,
	winrmProtocol string,
) error {
	connection, err := s.createConnection(
		osType,
		targetMachine,
		username,
		password,
		privateKeyPath,
		privateKeyContents,
		retryCount,
		retryDelay,
		winrmProtocol,
	)
	if err != nil {
		return fmt.Errorf("failed to create connection: %w", err)
	}
	defer func(connection connections.IdsecConnection) {
		err := connection.Disconnect()
		if err != nil {
			s.Logger.Warning("failed to disconnect: %v", err)
		}
	}(connection)

	cmdSet := buildCmdSet(installationPath)[osType]

	s.cleanupConnectorOnMachine(connection, cmdSet)
	return nil
}

func (s *IdsecCmgrConnectorsService) deleteConnector(connectorID string, retryCount int, retryDelay int) error {
	s.Logger.Info("Deleting connector [%s] from platform", connectorID)
	currentTryCount := 0
	for {
		response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(connectorURL, connectorID), nil, nil)
		if err != nil {
			return err
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				common.GlobalLogger.Warning("Error closing response body")
			}
		}(response.Body)
		if response.StatusCode != http.StatusNoContent {
			if currentTryCount < retryCount {
				currentTryCount++
				s.Logger.Warning("Failed to delete connector, retrying... [%d/%d]", currentTryCount, retryCount)
				time.Sleep(time.Duration(retryDelay) * time.Second)
				continue
			}
			return fmt.Errorf("failed to delete connector - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		}
		break
	}
	return nil
}

// Uninstall uninstalls a management agent connector from the target machine and removes it from the platform.
func (s *IdsecCmgrConnectorsService) Uninstall(req *connectorsmodels.IdsecCmgrUninstall) error {
	s.Logger.Info(
		"Uninstalling management agent connector [%s] from machine [%s] of type [%s]",
		req.ConnectorID,
		req.TargetMachine,
		req.ConnectorOS,
	)
	err := s.uninstallConnectorOnMachine(
		req.ConnectorOS,
		req.InstallationPath,
		req.TargetMachine,
		req.Username,
		req.Password,
		strings.TrimSuffix(common.ExpandFolder(req.PrivateKeyPath), "/"),
		req.PrivateKeyContents,
		req.RetryCount,
		req.RetryDelay,
		req.WinRMProtocol,
	)
	if req.ForceDelete || err == nil {
		return s.deleteConnector(req.ConnectorID, req.RetryCount, req.RetryDelay)
	}
	return err
}

// ServiceConfig returns the service configuration for IdsecCmgrConnectorsService.
func (s *IdsecCmgrConnectorsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
