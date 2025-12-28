package access

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
	accessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access/models"
)

const (
	connectorsURL                = "/api/connectors"
	connectorURL                 = "/api/connectors/%s"
	connectorSetupScriptURL      = "/api/connectors/setup-script"
	connectorTestReachabilityURL = "/api/connectors/%s/reachability"
	connectorMaintenanceURL      = "/api/connectors/%s/maintenance"

	// Linux / Darwin Commands
	unixStopConnectorServiceCmd   = "sudo systemctl stop cyberark-dpa-connector"
	unixRemoveConnectorServiceCmd = "sudo rm -f /etc/systemd/system/cyberark-dpa-connector.service && sudo rm -f /usr/lib/systemd/system/cyberark-dpa-connector.service && sudo systemctl daemon-reload && sudo systemctl reset-failed"
	unixRemoveConnectorFilesCmd   = "sudo rm -rf /opt/cyberark/connector"
	unixConnectorActiveCmd        = "sudo systemctl is-active --quiet cyberark-dpa-connector"
	unixReadConnectorConfigCmd    = "sudo cat /opt/cyberark/connector/connector.config.json"

	// Windows Commands
	winStopConnectorServiceCmd   = "Stop-Service -Name \"CyberArkDPAConnector\""
	winRemoveConnectorServiceCmd = `$service = Get-WmiObject -Class Win32_Service -Filter "Name='CyberArkDPAConnector'"; $service.delete()`
	winRemoveConnectorFilesCmd   = "Remove-Item -LiteralPath \"C:\\Program Files\\CyberArk\\DPAConnector\" -Force -Recurse"
	winConnectorActiveCmd        = `$result = Get-Service -Name "CyberArkDPAConnector"; if ($result.Status -ne 'Running') { return 1 }`
	winReadConnectorConfigCmd    = "Get-Content -Path \"C:\\Program Files\\CyberArk\\DPAConnector\\connector.config.json\""

	// Retry Constants
	connectorInstallRetryCount = 10
	connectorInstallRetryTick  = 10.0 * time.Second
	connectorReadyRetryCount   = 10
	connectorRetryTick         = 3.0 * time.Second
)

// ConnectorCmdSet maps OS types to their respective command sets.
var connectorCmdSet = map[string]map[string]string{
	commonmodels.OSTypeLinux: {
		"stopConnectorService":   unixStopConnectorServiceCmd,
		"removeConnectorService": unixRemoveConnectorServiceCmd,
		"removeConnectorFiles":   unixRemoveConnectorFilesCmd,
		"connectorActive":        unixConnectorActiveCmd,
		"readConnectorConfig":    unixReadConnectorConfigCmd,
	},
	commonmodels.OSTypeDarwin: {
		"stopConnectorService":   unixStopConnectorServiceCmd,
		"removeConnectorService": unixRemoveConnectorServiceCmd,
		"removeConnectorFiles":   unixRemoveConnectorFilesCmd,
		"connectorActive":        unixConnectorActiveCmd,
		"readConnectorConfig":    unixReadConnectorConfigCmd,
	},
	commonmodels.OSTypeWindows: {
		"stopConnectorService":   winStopConnectorServiceCmd,
		"removeConnectorService": winRemoveConnectorServiceCmd,
		"removeConnectorFiles":   winRemoveConnectorFilesCmd,
		"connectorActive":        winConnectorActiveCmd,
		"readConnectorConfig":    winReadConnectorConfigCmd,
	},
}
var connectorInstallRetryErrors = []string{
	"invalid content type",
}

// IdsecSIAAccessService is a struct that implements the IdsecService interface and provides functionality for Connectors of SIA.
type IdsecSIAAccessService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient

	doGet func(ctx context.Context, path string, params map[string]string) (*http.Response, error)
}

// NewIdsecSIAAccessService creates a new instance of IdsecSIAAccessService with the provided authenticators.
func NewIdsecSIAAccessService(authenticators ...auth.IdsecAuth) (*IdsecSIAAccessService, error) {
	accessService := &IdsecSIAAccessService{}
	var accessServiceInterface services.IdsecService = accessService
	baseService, err := services.NewIdsecBaseService(accessServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", accessService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	accessService.client = client
	accessService.ispAuth = ispAuth
	accessService.IdsecBaseService = baseService
	return accessService, nil
}

func (s *IdsecSIAAccessService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSIAAccessService) createConnection(
	osType string,
	targetMachine string,
	username string,
	password string,
	privateKeyPath string,
	privateKeyContents string,
	retryCount int,
	retryDelay int,
	winrmProtocol string,
) (connections.IdsecConnection, map[string]string, error) {
	var connection connections.IdsecConnection
	var connectionDetails *connectionsmodels.IdsecConnectionDetails

	if osType == commonmodels.OSTypeWindows {
		protocol := winrm.WinRMHTTPSPort
		if strings.ToLower(winrmProtocol) == "http" {
			protocol = winrm.WinRMHTTPPort
		}
		connection = winrm.NewIdsecWinRMConnection()
		connectionDetails = &connectionsmodels.IdsecConnectionDetails{
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
	} else {
		connection = ssh.NewIdsecSSHConnection()
		connectionDetails = &connectionsmodels.IdsecConnectionDetails{
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
	}

	if err := connection.Connect(connectionDetails); err != nil {
		return nil, nil, fmt.Errorf("failed to connect: %w", err)
	}

	return connection, connectorCmdSet[osType], nil
}

func (s *IdsecSIAAccessService) installConnectorOnMachine(
	installScript string,
	osType string,
	targetMachine string,
	username string,
	password string,
	privateKeyPath string,
	privateKeyContents string,
	retryCount int,
	retryDelay int,
	winrmProtocol string,
) (*accessmodels.IdsecSIAAccessConnectorID, error) {
	// Create connection
	connection, cmdSet, err := s.createConnection(
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

	// Run commands to stop, remove service, and remove files
	_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["stopConnectorService"],
	})
	if err != nil {
		s.Logger.Debug("failed to stop existing connector service (if any): %v", err)
	}
	_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["removeConnectorService"],
	})
	if err != nil {
		s.Logger.Debug("failed to remove existing connector service (if any): %v", err)
	}
	_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["removeConnectorFiles"],
	})
	if err != nil {
		s.Logger.Debug("failed to remove existing connector files (if any): %v", err)
	}

	// Install the connector
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
			Command: installScript,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to install connector: %w", err)
	}

	// Retry checking if the connector is active
	currConnReadyRetryCount := connectorReadyRetryCount
	for {
		_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
			Command: cmdSet["connectorActive"],
		})
		if err == nil {
			break
		}
		if currConnReadyRetryCount > 0 {
			currConnReadyRetryCount--
			time.Sleep(connectorRetryTick)
			continue
		}
		return nil, fmt.Errorf("failed to check if connector is active: %w", err)
	}

	// Read the connector configuration
	result, err := connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["readConnectorConfig"],
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read connector config: %w", err)
	}

	// Parse the connector configuration and return the ID
	var connectorConfig map[string]interface{}
	if err := json.Unmarshal([]byte(result.Stdout), &connectorConfig); err != nil {
		return nil, fmt.Errorf("failed to parse connector config: %w", err)
	}
	connectorID, ok := connectorConfig["Id"].(string)
	if !ok {
		return nil, fmt.Errorf("connector ID not found in config")
	}
	return &accessmodels.IdsecSIAAccessConnectorID{ConnectorID: connectorID}, nil
}

func (s *IdsecSIAAccessService) uninstallConnectorOnMachine(
	osType string,
	targetMachine string,
	username string,
	password string,
	privateKeyPath string,
	privateKeyContents string,
	retryCount int,
	retryDelay int,
	winrmProtocol string,
) error {
	// Create connection
	connection, cmdSet, err := s.createConnection(
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

	// Run commands to stop, remove service, and remove files
	_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["stopConnectorService"],
	})
	if err != nil {
		return fmt.Errorf("failed to stop connector service: %w", err)
	}

	_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["removeConnectorService"],
	})
	if err != nil {
		return fmt.Errorf("failed to remove connector service: %w", err)
	}

	_, err = connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: cmdSet["removeConnectorFiles"],
	})
	if err != nil {
		return fmt.Errorf("failed to remove connector files: %w", err)
	}

	return nil
}

// TestConnectorReachability tests the reachability of a connector.
func (s *IdsecSIAAccessService) TestConnectorReachability(testReachabilityRequest *accessmodels.IdsecSIATestConnectorReachability) (*accessmodels.IdsecSIAReachabilityTestResponse, error) {
	s.Logger.Info("Starting connector reachability test. ConnectorID: %s", testReachabilityRequest.ConnectorID)
	var testReachabilityRequestJSON = map[string]interface{}{
		"targets": []map[string]interface{}{
			{
				"hostname": testReachabilityRequest.TargetHostname,
				"port":     testReachabilityRequest.TargetPort,
			},
		},
		"checkBackendEndpoints": testReachabilityRequest.CheckBackendEndpoints,
	}
	response, err := s.client.Post(context.Background(), fmt.Sprintf(connectorTestReachabilityURL, testReachabilityRequest.ConnectorID), testReachabilityRequestJSON)
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
		return nil, fmt.Errorf("failed to test connector reachability - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	reachabilityTestResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var testResponse accessmodels.IdsecSIAReachabilityTestResponse
	err = mapstructure.Decode(reachabilityTestResponseJSON, &testResponse)
	if err != nil {
		return nil, err
	}
	return &testResponse, nil
}

// ConnectorSetupScript creates the setup script for the connector.
func (s *IdsecSIAAccessService) ConnectorSetupScript(getConnectorSetupScript *accessmodels.IdsecSIAGetConnectorSetupScript) (*accessmodels.IdsecSIAConnectorSetupScript, error) {
	s.Logger.Info("Retrieving new connector setup script")
	var getConnectorSetupScriptJSON map[string]interface{}
	err := mapstructure.Decode(getConnectorSetupScript, &getConnectorSetupScriptJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Post(context.Background(), connectorSetupScriptURL, getConnectorSetupScriptJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to retrieve connector setup script - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	connectorSetupScriptJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var setupScript accessmodels.IdsecSIAConnectorSetupScript
	err = mapstructure.Decode(connectorSetupScriptJSON, &setupScript)
	if err != nil {
		return nil, err
	}
	return &setupScript, nil
}

// InstallConnector installs the connector on the target machine.
func (s *IdsecSIAAccessService) InstallConnector(installConnector *accessmodels.IdsecSIAInstallConnector) (*accessmodels.IdsecSIAAccessConnectorID, error) {
	s.Logger.Info(
		"Installing connector on machine [%s] of type [%s]",
		installConnector.TargetMachine,
		installConnector.ConnectorOS,
	)
	installationScript, err := s.ConnectorSetupScript(&accessmodels.IdsecSIAGetConnectorSetupScript{
		ConnectorOS:     installConnector.ConnectorOS,
		ConnectorPoolID: installConnector.ConnectorPoolID,
		ConnectorType:   installConnector.ConnectorType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve connector setup script: %w", err)
	}
	return s.installConnectorOnMachine(
		installationScript.BashCmd,
		installConnector.ConnectorOS,
		installConnector.TargetMachine,
		installConnector.Username,
		installConnector.Password,
		strings.TrimSuffix(common.ExpandFolder(installConnector.PrivateKeyPath), "/"),
		installConnector.PrivateKeyContents,
		installConnector.RetryCount,
		installConnector.RetryDelay,
		installConnector.WinRMProtocol,
	)
}

// UninstallConnector uninstalls the connector from the target machine.
func (s *IdsecSIAAccessService) UninstallConnector(uninstallConnector *accessmodels.IdsecSIAUninstallConnector) error {
	s.Logger.Info(
		"Uninstalling connector [%s] from machine",
		uninstallConnector.ConnectorID,
	)
	err := s.uninstallConnectorOnMachine(
		uninstallConnector.ConnectorOS,
		uninstallConnector.TargetMachine,
		uninstallConnector.Username,
		uninstallConnector.Password,
		strings.TrimSuffix(common.ExpandFolder(uninstallConnector.PrivateKeyPath), "/"),
		uninstallConnector.PrivateKeyContents,
		uninstallConnector.RetryCount,
		uninstallConnector.RetryDelay,
		uninstallConnector.WinRMProtocol,
	)
	if err != nil {
		return err
	}
	return s.DeleteConnector(&accessmodels.IdsecSIADeleteConnector{
		ConnectorID: uninstallConnector.ConnectorID,
		RetryCount:  uninstallConnector.RetryCount,
		RetryDelay:  uninstallConnector.RetryDelay,
	})
}

// DeleteConnector deletes the connector from the target machine.
func (s *IdsecSIAAccessService) DeleteConnector(deleteConnector *accessmodels.IdsecSIADeleteConnector) error {
	s.Logger.Info(
		"Deleting connector [%s] from machine",
		deleteConnector.ConnectorID,
	)
	currentTryCount := 0
	for {
		response, err := s.client.Delete(context.Background(), fmt.Sprintf(connectorURL, deleteConnector.ConnectorID), nil, nil)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK {
			if currentTryCount < deleteConnector.RetryCount {
				currentTryCount++
				s.Logger.Warning("Failed to delete connector, retrying... [%d/%d]", currentTryCount, deleteConnector.RetryCount)
				time.Sleep(time.Duration(deleteConnector.RetryDelay) * time.Second)
				continue
			}
			return fmt.Errorf("failed to delete connector - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		}
		break
	}
	return nil
}

// ListConnectors list of SIA connectors
func (s *IdsecSIAAccessService) ListConnectors() (*accessmodels.IdsecSIAConnectorsListResponse, error) {
	s.Logger.Info("List connectors")

	getFn := s.doGet
	if getFn == nil {
		getFn = func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
			return s.client.Get(ctx, path, params)
		}
	}

	response, err := getFn(context.Background(), connectorsURL, nil)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list connectors - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	listResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var listResponse accessmodels.IdsecSIAConnectorsListResponse
	err = mapstructure.Decode(listResponseJSON, &listResponse)
	if err != nil {
		return nil, nil
	}
	return &listResponse, nil
}

// UpdateConnectorMaintenanceMode updates (enable/disable) maintenance mode on a connector.
func (s *IdsecSIAAccessService) UpdateConnectorMaintenanceMode(maintenanceConnector *accessmodels.IdsecSIAMaintenanceConnector) (*accessmodels.IdsecSIAMaintenanceConnectorStatus, error) {
	s.Logger.Info(
		"Setting maintenance mode to [%t] on connector [%s]",
		maintenanceConnector.Maintenance,
		maintenanceConnector.ConnectorID,
	)

	requestBody := map[string]interface{}{
		"maintenance": maintenanceConnector.Maintenance,
	}

	currentTryCount := 0
	for {
		response, err := s.client.Put(context.Background(), fmt.Sprintf(connectorMaintenanceURL, maintenanceConnector.ConnectorID), requestBody)
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
			if currentTryCount < maintenanceConnector.RetryCount {
				currentTryCount++
				s.Logger.Warning("Failed to update connector maintenance mode, retrying... [%d/%d]", currentTryCount, maintenanceConnector.RetryCount)
				time.Sleep(time.Duration(maintenanceConnector.RetryDelay) * time.Second)
				continue
			}
			return nil, fmt.Errorf("failed to update connector maintenance mode - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		}

		// Deserialize response using standard pattern (same as ListConnectors)
		statusResponseJSON, err := common.DeserializeJSONSnake(response.Body)
		if err != nil {
			return nil, err
		}
		var status accessmodels.IdsecSIAMaintenanceConnectorStatus
		err = mapstructure.Decode(statusResponseJSON, &status)
		if err != nil {
			return nil, err
		}
		return &status, nil
	}
}

// ServiceConfig returns the service configuration for the IdsecSIAAccessService.
func (s *IdsecSIAAccessService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
