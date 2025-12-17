package sshca

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections/ssh"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	connectionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections/connectiondata"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sshcamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca/models"
)

const (
	generateNewCAKeyURL        = "api/public-keys/rotation/generate-new"
	deactivatePreviousCAKeyURL = "api/public-keys/rotation/deactivate-previous"
	reactivatePreviousCAKeyURL = "api/public-keys/rotation/reactivate-previous"
	publicKeyURL               = "api/public-keys"
	publicKeyScriptURL         = "api/public-keys/scripts"
	defaultShellType           = "bash"
)

const (
	isInstalledScriptBash = `sudo bash <<'EOF'
#!/usr/bin/env bash
set -o errexit
set -o noclobber
set -o nounset
set -o pipefail

clear || true

# Check if script is running as sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# check if sshd config file exists
sshd_config_filename='/etc/ssh/sshd_config'
if [[ ! -f "$sshd_config_filename" ]]; then
    echo "$sshd_config_filename doesnt exists. exiting"
    exit 1
fi

ca_filename='SIA_ssh_public_CA.pub'
target_ca_filename='/etc/ssh/'$ca_filename
expected_ca='%s'

echo "Checking CyberArk SSH CA installation status..."
echo "================================================"

# Check if TrustedUserCAKeys exists in config
config_ca_line=$(grep "^TrustedUserCAKeys" $sshd_config_filename 2>/dev/null || echo "")

if [[ -z "$config_ca_line" ]]; then
    echo "Status: NOT INSTALLED"
    echo "Reason: No TrustedUserCAKeys configuration found in $sshd_config_filename"
    exit 2
fi

# Get the configured CA file path
config_ca_filename=$(echo "$config_ca_line" | awk '{print $2}')
echo "Found TrustedUserCAKeys configuration: $config_ca_filename"

# Check if it points to our specific CA file
if [[ "$config_ca_filename" != "$target_ca_filename" ]]; then
    echo "Status: DIFFERENT CA INSTALLED"
    echo "Reason: Configuration points to different CA file"
    echo "  Configured: $config_ca_filename"
    echo "  Expected:   $target_ca_filename"
    exit 3
fi

# Check if CA file exists
if [[ ! -f "$target_ca_filename" ]]; then
    echo "Status: MISCONFIGURED"
    echo "Reason: Configuration exists but CA file is missing: $target_ca_filename"
    exit 1
fi

# Check if CA file contains our expected key
actual_ca=$(cat "$target_ca_filename")
if [[ "$actual_ca" != "$expected_ca" ]]; then
    echo "Status: DIFFERENT CA INSTALLED"
    echo "Reason: CA file exists but contains different key than expected CyberArk CA"
    echo "Location: $target_ca_filename"
    exit 3
fi

# All checks passed
echo "Status: INSTALLED"
echo "CyberArk SSH CA is properly installed and configured"
echo "CA File: $target_ca_filename"
echo "Config:  $sshd_config_filename"
exit 0
EOF`
	isInstalledScriptKsh = `sudo ksh <<'EOF'
#!/usr/bin/env ksh
set -o errexit
set -o noclobber
set -o nounset

clear || true

# Check if script is running as sudo
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# check if sshd config file exists
sshd_config_filename='/etc/ssh/sshd_config'
if [[ ! -f "$sshd_config_filename" ]]; then
    echo "$sshd_config_filename doesnt exists. exiting"
    exit 1
fi

ca_filename='SIA_ssh_public_CA.pub'
target_ca_filename='/etc/ssh/'$ca_filename
expected_ca='%s'

echo "Checking CyberArk SSH CA installation status..."
echo "================================================"

# Check if TrustedUserCAKeys exists in config
config_ca_line=$(grep "^TrustedUserCAKeys" $sshd_config_filename 2>/dev/null || echo "")

if [[ -z "$config_ca_line" ]]; then
    echo "Status: NOT INSTALLED"
    echo "Reason: No TrustedUserCAKeys configuration found in $sshd_config_filename"
    exit 2
fi

# Get the configured CA file path
config_ca_filename=$(echo "$config_ca_line" | awk '{print $2}')
echo "Found TrustedUserCAKeys configuration: $config_ca_filename"

# Check if it points to our specific CA file
if [[ "$config_ca_filename" != "$target_ca_filename" ]]; then
    echo "Status: DIFFERENT CA INSTALLED"
    echo "Reason: Configuration points to different CA file"
    echo "  Configured: $config_ca_filename"
    echo "  Expected:   $target_ca_filename"
    exit 3
fi

# Check if CA file exists
if [[ ! -f "$target_ca_filename" ]]; then
    echo "Status: MISCONFIGURED"
    echo "Reason: Configuration exists but CA file is missing: $target_ca_filename"
    exit 1
fi

# Check if CA file contains our expected key
actual_ca=$(cat "$target_ca_filename")
if [[ "$actual_ca" != "$expected_ca" ]]; then
    echo "Status: DIFFERENT CA INSTALLED"
    echo "Reason: CA file exists but contains different key than expected CyberArk CA"
    echo "Location: $target_ca_filename"
    exit 3
fi

# All checks passed
echo "Status: INSTALLED"
echo "CyberArk SSH CA is properly installed and configured"
echo "CA File: $target_ca_filename"
echo "Config:  $sshd_config_filename"
exit 0
EOF`
	uninstallScriptBash = `sudo bash <<'EOF'
#!/usr/bin/env bash
set -o errexit
set -o noclobber
set -o nounset
set -o pipefail

set -e  # exit if any subcommand fails

clear || true

# Check if script is running as sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# check if sshd config file exists
sshd_config_filename='/etc/ssh/sshd_config'
if [[ ! -f "$sshd_config_filename" ]]; then
    echo "$sshd_config_filename doesnt exists. exiting"
    exit 1
fi

sshd_path=$(which sshd)
ca_filename='SIA_ssh_public_CA.pub'
target_ca_filename='/etc/ssh/'$ca_filename
expected_ca='%s'

# Check if TrustedUserCAKeys exists in config and points to our CA file
config_ca_line=$(grep "^TrustedUserCAKeys" $sshd_config_filename || echo "")

if [[ -n "$config_ca_line" ]]; then
    config_ca_filename=$(echo "$config_ca_line" | awk '{print $2}')
    
    # Check if it points to our specific CA file
    if [[ "$config_ca_filename" == "$target_ca_filename" ]]; then
        # Verify the CA file exists and contains our expected CA key
        if [[ -f "$target_ca_filename" ]]; then
            actual_ca=$(cat "$target_ca_filename")
            if [[ "$actual_ca" != "$expected_ca" ]]; then
                echo "Warning: CA file exists but contains different content than expected"
                echo "Found CA at $target_ca_filename but it's not our CyberArk CA"
                echo "Aborting removal to prevent affecting other configurations"
                exit 1
            fi
        fi
        
        echo "Found our CyberArk CA configuration. Removing..."
        
        # Backing up the config file
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        
        # Remove the TrustedUserCAKeys line from sshd_config
        sed -i.tmp '/^TrustedUserCAKeys/d' $sshd_config_filename
        rm -f $sshd_config_filename.tmp
        
        # Remove the CA file if it exists
        if [[ -f "$target_ca_filename" ]]; then
            rm -f $target_ca_filename
            echo "Removed CA file: $target_ca_filename"
        fi
        
        # Check new configuration and revert if with errors
        config_ok=$($sshd_path -t > /dev/null 2>&1; echo $?)
        if [ $config_ok -ne 0 ]; then
            mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
            echo "Error: Configuration test failed. Reverting changes."
            exit 1
        fi
        
        echo "Configuration updated successfully"
        
        # Capture the output of systemctl list-units
        services_output=$(systemctl list-units --type=service --all 2>/dev/null || echo "")
        
        # Check the sshd service name
        if echo "$services_output" | grep -q "ssh.service"; then
           ssh_service="ssh.service"
        else
           ssh_service="sshd.service"
        fi
        
        # Restart the sshd server
        os_name=$(uname -s)
        if [[ $os_name == "SunOS" ]]; then
            restart_command="svcadm restart network/ssh"
        elif [[ $os_name == "AIX" ]]; then
            restart_command="stopsrc -s sshd && startsrc -s sshd"
        else
            restart_command="systemctl restart $ssh_service"
        fi
        
        $restart_command
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            echo "sshd service restarted successfully"
            echo "CA removal completed successfully"
        else
            echo "Fatal Error: sshd service failed to restart"
            echo "Please start the sshd server manually"
            exit 1
        fi
    else
        echo "Found TrustedUserCAKeys configuration but it points to a different CA file:"
        echo "  Configured: $config_ca_filename"
        echo "  Expected:   $target_ca_filename"
        echo "Aborting removal to prevent affecting other configurations"
        exit 1
    fi
else
    echo "No TrustedUserCAKeys configuration found"
    echo "Nothing to remove"
    exit 0
fi
EOF`
	uninstallScriptKsh = `sudo ksh <<'EOF'
#!/usr/bin/env ksh
set -o errexit
set -o noclobber
set -o nounset

set -e  # exit if any subcommand fails

clear || true

# Check if script is running as sudo
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# check if sshd config file exists
sshd_config_filename='/etc/ssh/sshd_config'
if [[ ! -f "$sshd_config_filename" ]]; then
    echo "$sshd_config_filename doesnt exists. exiting"
    exit 1
fi

sshd_path=$(command -v sshd)
ca_filename='SIA_ssh_public_CA.pub'
target_ca_filename='/etc/ssh/'$ca_filename
expected_ca='%s'

# Check if TrustedUserCAKeys exists in config and points to our CA file
config_ca_line=$(grep "^TrustedUserCAKeys" $sshd_config_filename 2>/dev/null || echo "")

if [[ -n "$config_ca_line" ]]; then
    config_ca_filename=$(echo "$config_ca_line" | awk '{print $2}')
    
    # Check if it points to our specific CA file
    if [[ "$config_ca_filename" == "$target_ca_filename" ]]; then
        # Verify the CA file exists and contains our expected CA key
        if [[ -f "$target_ca_filename" ]]; then
            actual_ca=$(cat "$target_ca_filename")
            if [[ "$actual_ca" != "$expected_ca" ]]; then
                echo "Warning: CA file exists but contains different content than expected"
                echo "Found CA at $target_ca_filename but it's not our CyberArk CA"
                echo "Aborting removal to prevent affecting other configurations"
                exit 1
            fi
        fi
        
        echo "Found our CyberArk CA configuration. Removing..."
        
        # Backing up the config file
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        
        # Remove the TrustedUserCAKeys line from sshd_config
        grep -v "^TrustedUserCAKeys" $sshd_config_filename > $sshd_config_filename.tmp
        mv $sshd_config_filename.tmp $sshd_config_filename
        
        # Remove the CA file if it exists
        if [[ -f "$target_ca_filename" ]]; then
            rm -f $target_ca_filename
            echo "Removed CA file: $target_ca_filename"
        fi
        
        # Check new configuration and revert if with errors
        config_ok=$($sshd_path -t > /dev/null 2>&1; echo $?)
        if [ $config_ok -ne 0 ]; then
            mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
            echo "Error: Configuration test failed. Reverting changes."
            exit 1
        fi
        
        echo "Configuration updated successfully"
        
        # Restart the sshd server
        os_name=$(uname -s)
        if [[ $os_name == "SunOS" ]]; then
            svcadm restart network/ssh;
        elif [[ $os_name == "AIX" ]]; then
            stopsrc -s sshd > /dev/null;
            startsrc -s sshd > /dev/null;
        else
            systemctl restart sshd;
        fi
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            echo "sshd service restarted successfully"
            echo "CA removal completed successfully"
        else
            echo "Fatal Error: sshd service failed to restart"
            echo "Please start the sshd server manually"
            exit 1
        fi
    else
        echo "Found TrustedUserCAKeys configuration but it points to a different CA file:"
        echo "  Configured: $config_ca_filename"
        echo "  Expected:   $target_ca_filename"
        echo "Aborting removal to prevent affecting other configurations"
        exit 1
    fi
else
    echo "No TrustedUserCAKeys configuration found"
    echo "Nothing to remove"
    exit 0
fi
EOF`
)

// IdsecSIASSHCAService is a struct that implements the IdsecService interface and provides functionality for SSH CA of SIA.
type IdsecSIASSHCAService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient

	doGet         func(ctx context.Context, path string, params interface{}) (*http.Response, error)
	doPost        func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	newConnection func() connections.IdsecConnection
}

// NewIdsecSIASSHCAService creates a new instance of IdsecSIASSHCAService with the provided authenticators.
func NewIdsecSIASSHCAService(authenticators ...auth.IdsecAuth) (*IdsecSIASSHCAService, error) {
	sshCaService := &IdsecSIASSHCAService{}
	var sshCaServiceInterface services.IdsecService = sshCaService
	baseService, err := services.NewIdsecBaseService(sshCaServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", sshCaService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	sshCaService.client = client
	sshCaService.ispAuth = ispAuth
	sshCaService.IdsecBaseService = baseService
	return sshCaService, nil
}

func (s *IdsecSIASSHCAService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSIASSHCAService) getOperation() func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	if s.doGet != nil {
		return s.doGet
	}
	return s.client.Get
}

func (s *IdsecSIASSHCAService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPost != nil {
		return s.doPost
	}
	return s.client.Post
}

func (s *IdsecSIASSHCAService) newSSHConnection() connections.IdsecConnection {
	if s.newConnection != nil {
		return s.newConnection()
	}
	return ssh.NewIdsecSSHConnection()
}

// GenerateNewCA generates a new CA key version.
func (s *IdsecSIASSHCAService) GenerateNewCA() error {
	s.Logger.Info("Generate new CA key version")
	response, err := s.postOperation()(context.Background(), generateNewCAKeyURL, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to generate new CA key  - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// DeactivatePreviousCa Deactivate previous CA key version.
func (s *IdsecSIASSHCAService) DeactivatePreviousCa() error {
	s.Logger.Info("Deactivate previous CA key version")
	response, err := s.postOperation()(context.Background(), deactivatePreviousCAKeyURL, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to deactivate previous CA key  - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ReactivatePreviousCa Deactivate previous CA key version.
func (s *IdsecSIASSHCAService) ReactivatePreviousCa() error {
	s.Logger.Info("Reactivate previous CA key version")
	response, err := s.postOperation()(context.Background(), reactivatePreviousCAKeyURL, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to reactivate previous CA key  - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// PublicKey retrieves the public key for the SSH CA.
func (s *IdsecSIASSHCAService) PublicKey(getPublicKey *sshcamodels.IdsecSIAGetSSHPublicKey) (string, error) {
	s.Logger.Info("Getting public key")
	response, err := s.getOperation()(context.Background(), publicKeyURL, nil)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get public key  - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	publicKey, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if getPublicKey != nil && getPublicKey.OutputFile != "" {
		file, err := os.Create(getPublicKey.OutputFile)
		if err != nil {
			return "", err
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				s.Logger.Warning("Error closing output file")
			}
		}(file)
		_, err = file.Write(publicKey)
		if err != nil {
			return "", err
		}
	}
	return string(publicKey), nil
}

// PublicKeyScript retrieves the public key script for the SSH CA.
func (s *IdsecSIASSHCAService) PublicKeyScript(getPublicKeyScript *sshcamodels.IdsecSIAGetSSHPublicKeyScript) (string, error) {
	s.Logger.Info("Getting public key script")
	params := map[string]string{
		"scriptType": defaultShellType,
	}
	if getPublicKeyScript != nil && getPublicKeyScript.Shell != "" {
		params["scriptType"] = getPublicKeyScript.Shell
	}
	response, err := s.getOperation()(context.Background(), publicKeyScriptURL, params)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get public key script  - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	publicKeyScriptRaw, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	publicKeyScriptJSON := map[string]interface{}{}
	err = json.Unmarshal(publicKeyScriptRaw, &publicKeyScriptJSON)
	if err != nil {
		return "", err
	}
	b64Cmd, ok := publicKeyScriptJSON["base64_cmd"].(string)
	if !ok {
		return "", fmt.Errorf("failed to parse public key script response")
	}
	publicKeyScript, err := base64.StdEncoding.DecodeString(b64Cmd)
	if err != nil {
		return "", err
	}
	if getPublicKeyScript != nil && getPublicKeyScript.OutputFile != "" {
		file, err := os.Create(getPublicKeyScript.OutputFile)
		if err != nil {
			return "", err
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				s.Logger.Warning("Error closing output file")
			}
		}(file)
		_, err = file.Write(publicKeyScript)
		if err != nil {
			return "", err
		}
	}
	return string(publicKeyScript), nil
}

// InstallPublicKey installs the public key on the target machine.
func (s *IdsecSIASSHCAService) InstallPublicKey(installPublicKey *sshcamodels.IdsecSIAInstallSSHPublicKey) (*sshcamodels.IdsecSIASSHPublicKeyOperationResult, error) {
	s.Logger.Info("Installing public key on target machine")
	// Get the script
	publicKeyScript, err := s.PublicKeyScript(&sshcamodels.IdsecSIAGetSSHPublicKeyScript{
		Shell: installPublicKey.Shell,
	})
	if err != nil {
		return nil, err
	}

	// Create connection
	connection := s.newSSHConnection()
	connectionDetails := &connectionsmodels.IdsecConnectionDetails{
		Address:        installPublicKey.TargetMachine,
		Port:           ssh.SSHPort,
		ConnectionType: connectionsmodels.SSH,
		Credentials: &connectionsmodels.IdsecConnectionCredentials{
			User:               installPublicKey.Username,
			Password:           installPublicKey.Password,
			PrivateKeyFilepath: strings.TrimSuffix(common.ExpandFolder(installPublicKey.PrivateKeyPath), "/"),
			PrivateKeyContents: installPublicKey.PrivateKeyContents,
		},
		ConnectionData:    &connectiondata.IdsecSSHConnectionData{},
		ConnectionRetries: installPublicKey.RetryCount,
		RetryTickPeriod:   installPublicKey.RetryDelay,
	}

	if err := connection.Connect(connectionDetails); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer func(connection connections.IdsecConnection) {
		err := connection.Disconnect()
		if err != nil {
			s.Logger.Warning("failed to disconnect: %v", err)
		}
	}(connection)

	// Check if already installed
	checkScript := ""
	if installPublicKey.Shell == "kornShell" {
		checkScript = fmt.Sprintf(isInstalledScriptKsh, "%s")
	} else {
		checkScript = fmt.Sprintf(isInstalledScriptBash, "%s")
	}
	checkResult, err := connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command:  checkScript,
		IgnoreRC: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run installation check command: %w", err)
	}
	switch checkResult.RC {
	case 0:
		s.Logger.Info("Public key is already installed on target machine")
		return &sshcamodels.IdsecSIASSHPublicKeyOperationResult{Result: true, Message: "Public key is already installed on target machine"}, nil
	case 3:
		s.Logger.Info("Different public key is installed on target machine, proceeding with installation anyway")
	default:
		s.Logger.Info("Public key is not installed on target machine or not recognized, proceeding with installation")
	}

	// Run the installation script
	result, err := connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: publicKeyScript,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run command: %w", err)
	}
	if result.RC != 0 {
		return nil, fmt.Errorf("failed to install public key, exit code: %d, stderr: %s, stdout: %s", result.RC, result.Stderr, result.Stdout)
	}
	s.Logger.Info("Public key installed successfully")
	return &sshcamodels.IdsecSIASSHPublicKeyOperationResult{Result: true, Message: "Public key installed successfully"}, nil
}

// UninstallPublicKey uninstalls the public key from the target machine.
func (s *IdsecSIASSHCAService) UninstallPublicKey(uninstallPublicKey *sshcamodels.IdsecSIAUninstallSSHPublicKey) (*sshcamodels.IdsecSIASSHPublicKeyOperationResult, error) {
	s.Logger.Info("Uninstalling public key from target machine")
	// Get the public key
	publicKey, err := s.PublicKey(&sshcamodels.IdsecSIAGetSSHPublicKey{})
	if err != nil {
		return nil, err
	}

	// Choose uninstall script based on shell type
	var uninstallScript string
	if uninstallPublicKey.Shell == "kornShell" {
		uninstallScript = fmt.Sprintf(uninstallScriptKsh, publicKey)
	} else {
		uninstallScript = fmt.Sprintf(uninstallScriptBash, publicKey)
	}

	// Create connection
	connection := s.newSSHConnection()
	connectionDetails := &connectionsmodels.IdsecConnectionDetails{
		Address:        uninstallPublicKey.TargetMachine,
		Port:           ssh.SSHPort,
		ConnectionType: connectionsmodels.SSH,
		Credentials: &connectionsmodels.IdsecConnectionCredentials{
			User:               uninstallPublicKey.Username,
			Password:           uninstallPublicKey.Password,
			PrivateKeyFilepath: strings.TrimSuffix(common.ExpandFolder(uninstallPublicKey.PrivateKeyPath), "/"),
			PrivateKeyContents: uninstallPublicKey.PrivateKeyContents,
		},
		ConnectionData:    &connectiondata.IdsecSSHConnectionData{},
		ConnectionRetries: uninstallPublicKey.RetryCount,
		RetryTickPeriod:   uninstallPublicKey.RetryDelay,
	}

	if err := connection.Connect(connectionDetails); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer func(connection connections.IdsecConnection) {
		err := connection.Disconnect()
		if err != nil {
			s.Logger.Warning("failed to disconnect: %v", err)
		}
	}(connection)

	// Check if installed
	checkScript := ""
	if uninstallPublicKey.Shell == "kornShell" {
		checkScript = fmt.Sprintf(isInstalledScriptKsh, publicKey)
	} else {
		checkScript = fmt.Sprintf(isInstalledScriptBash, publicKey)
	}
	checkResult, err := connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command:  checkScript,
		IgnoreRC: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run uninstallation check command: %w", err)
	}

	switch checkResult.RC {
	case 0:
		s.Logger.Info("Public key is installed on target machine, proceeding with uninstallation")
	case 2:
		s.Logger.Info("Public key is not installed on target machine, nothing to uninstall")
		return &sshcamodels.IdsecSIASSHPublicKeyOperationResult{Result: true, Message: "Public key is not installed on target machine, nothing to uninstall"}, nil
	default:
		s.Logger.Info("Public key is not properly installed on target machine, proceeding with uninstallation anyway")

	}

	// Run the uninstallation script
	result, err := connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command: uninstallScript,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run command: %w", err)
	}
	if result.RC != 0 {
		return nil, fmt.Errorf("failed to uninstall public key, exit code: %d, stderr: %s, stdout: %s", result.RC, result.Stderr, result.Stdout)
	}
	s.Logger.Info("Public key uninstalled successfully")
	return &sshcamodels.IdsecSIASSHPublicKeyOperationResult{Result: true, Message: "Public key uninstalled successfully"}, nil
}

// IsPublicKeyInstalled checks if the public key is installed on the target machine.
func (s *IdsecSIASSHCAService) IsPublicKeyInstalled(isPublicKeyInstalled *sshcamodels.IdsecSIAIsSSHPublicKeyInstalled) (*sshcamodels.IdsecSIASSHPublicKeyOperationResult, error) {
	s.Logger.Info("Checking if public key is installed on target machine")
	// Get the public key
	publicKey, err := s.PublicKey(&sshcamodels.IdsecSIAGetSSHPublicKey{})
	if err != nil {
		return nil, err
	}

	// Create connection
	connection := s.newSSHConnection()
	connectionDetails := &connectionsmodels.IdsecConnectionDetails{
		Address:        isPublicKeyInstalled.TargetMachine,
		Port:           ssh.SSHPort,
		ConnectionType: connectionsmodels.SSH,
		Credentials: &connectionsmodels.IdsecConnectionCredentials{
			User:               isPublicKeyInstalled.Username,
			Password:           isPublicKeyInstalled.Password,
			PrivateKeyFilepath: strings.TrimSuffix(common.ExpandFolder(isPublicKeyInstalled.PrivateKeyPath), "/"),
			PrivateKeyContents: isPublicKeyInstalled.PrivateKeyContents,
		},
		ConnectionData:    &connectiondata.IdsecSSHConnectionData{},
		ConnectionRetries: isPublicKeyInstalled.RetryCount,
		RetryTickPeriod:   isPublicKeyInstalled.RetryDelay,
	}

	if err := connection.Connect(connectionDetails); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer func(connection connections.IdsecConnection) {
		err := connection.Disconnect()
		if err != nil {
			s.Logger.Warning("failed to disconnect: %v", err)
		}
	}(connection)

	// Check if installed
	checkScript := ""
	if isPublicKeyInstalled.Shell == "kornShell" {
		checkScript = fmt.Sprintf(isInstalledScriptKsh, publicKey)
	} else {
		checkScript = fmt.Sprintf(isInstalledScriptBash, publicKey)
	}
	checkResult, err := connection.RunCommand(&connectionsmodels.IdsecConnectionCommand{
		Command:  checkScript,
		IgnoreRC: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run installation check command: %w", err)
	}
	if checkResult.RC == 0 {
		s.Logger.Info("Public key is installed on target machine")
		return &sshcamodels.IdsecSIASSHPublicKeyOperationResult{Result: true, Message: "Public key is installed on target machine"}, nil
	}
	s.Logger.Info("Public key is not installed on target machine")
	return &sshcamodels.IdsecSIASSHPublicKeyOperationResult{Result: false, Message: "Public key is not installed on target machine"}, nil
}

// ServiceConfig returns the service configuration for the IdsecSIASSHCAService.
func (s *IdsecSIASSHCAService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
