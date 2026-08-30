package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr"
	connmgmtmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/connectors/models"
	networksmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/networks/models"
	poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"
)

// flowType enumerates the flows this example can run.
type flowType string

const (
	// installFlow creates a network and a pool, then installs a connector on the target machine.
	installFlow flowType = "install"
	// uninstallFlow uninstalls the connector configured in config.ConnectorID, and deletes the pool
	// and the network configured in config.PoolID and config.NetworkID when they are provided.
	uninstallFlow flowType = "uninstall"
	// installAndUninstallFlow installs a connector and uninstalls it only if the installation succeeded,
	// then deletes the pool and the network created by the installation.
	installAndUninstallFlow flowType = "install_and_uninstall"
	// installAndUpdateFlow creates a network and two pools, installs a connector on the first pool,
	// then reassigns it to the second pool via Update. Resources are kept after the flow completes.
	installAndUpdateFlow flowType = "install_and_update"
	// installAndUpdateAndUninstallFlow performs the same steps as installAndUpdateFlow, then
	// uninstalls the connector and deletes both pools and the network.
	installAndUpdateAndUninstallFlow flowType = "install_and_update_and_uninstall"
	// updateAndUninstallFlow uses an existing connector/pool/network from config, creates a second
	// pool on the same network, reassigns the connector to it via Update, then uninstalls the
	// connector and deletes both pools and the network.
	updateAndUninstallFlow flowType = "update_and_uninstall"
)

const (
	linuxOS   = "linux"
	windowsOS = "windows"
)

// linuxMachineConfig holds the SSH connection details of a Linux machine hosting the connector.
// Linux connectors are installed to a fixed path, so no installation path is configurable.
type linuxMachineConfig struct {
	TargetMachine  string
	Username       string
	PrivateKeyPath string
}

// windowsMachineConfig holds the WinRM connection details of a Windows machine hosting the connector.
type windowsMachineConfig struct {
	TargetMachine    string
	Username         string
	Password         string
	InstallationPath string
	// WinRMProtocol is either http or https.
	WinRMProtocol string
	// CertificatePath is the path to a custom CA certificate for HTTPS WinRM connections.
	CertificatePath string
	// TrustCertificate when true trusts any server certificate for HTTPS WinRM connections.
	TrustCertificate bool
}

// config holds every parameter used by the example flows.
type config struct {
	// Flow selects which of the three flows to run.
	Flow flowType
	// OSType is the operating system of the target machine (linuxOS or windowsOS).
	OSType string
	// ConnectorID is the connector to uninstall, used by uninstallFlow only.
	ConnectorID string
	// PoolID is the pool to delete after the connector is uninstalled, used by uninstallFlow only.
	// Leave it empty to keep the pool.
	PoolID string
	// NetworkID is the network to delete after the pool is deleted, used by uninstallFlow only.
	// Leave it empty to keep the network.
	NetworkID string
	// BaseResourceName prefixes the network and pool created by the install flows.
	BaseResourceName string

	TenantUsername string
	TenantSecret   string

	// LinuxMachine is used when OSType is linuxOS.
	LinuxMachine linuxMachineConfig
	// WindowsMachine is used when OSType is windowsOS.
	WindowsMachine windowsMachineConfig
}

func main() {
	cfg := &config{
		Flow:             installAndUninstallFlow,
		OSType:           windowsOS,
		ConnectorID:      "",
		PoolID:           "",
		NetworkID:        "",
		BaseResourceName: "B7",

		// Note: change to the environment of this tenant in the file "idsec_env.go" in GetDeployEnv() method
		TenantUsername: "<TENANT_ADMIN_LOGIN_NAME>",
		TenantSecret:   "<TENANT_ADMIN_PASSWORD>",

		LinuxMachine: linuxMachineConfig{
			TargetMachine:  "<EC2-MACHINE-PUBLIC-IP>",
			Username:       "ec2-user",
			PrivateKeyPath: "<EC2-KEY-PAIR-LOCAL-PATH>",
		},
		WindowsMachine: windowsMachineConfig{
			TargetMachine:    "<EC2-MACHINE-PUBLIC-IP>",
			Username:         "Administrator",
			Password:         "<EC2-ADMIN-PASSWORD>",
			InstallationPath: "",
			WinRMProtocol:    "https",
			CertificatePath:  "<SELF-SIGNED-CERT-PUBLIC-KEY-FROM-MACHINE",
			TrustCertificate: false,
		},
	}

	ispAuth, err := authenticate(cfg)
	if err != nil {
		panic(err)
	}

	cmgrAPI, err := cmgr.NewIdsecCmgrAPI(ispAuth)
	if err != nil {
		panic(err)
	}

	if err := runFlow(cmgrAPI, cfg); err != nil {
		panic(err)
	}
}

// authenticate performs an ISP authentication to the platform and returns the authenticated client.
func authenticate(cfg *config) (*auth.IdsecISPAuth, error) {
	ispAuth := auth.NewIdsecISPAuth(false)
	if _, err := ispAuth.Authenticate(
		nil,
		&authmodels.IdsecAuthProfile{
			Username:           cfg.TenantUsername,
			AuthMethod:         authmodels.Identity,
			AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{},
		},
		&authmodels.IdsecSecret{
			Secret: cfg.TenantSecret,
		},
		false,
		false,
	); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}
	return ispAuth.(*auth.IdsecISPAuth), nil
}

// runFlow runs the flow selected in the configuration.
func runFlow(cmgrAPI *cmgr.IdsecCmgrAPI, cfg *config) error {
	if cfg.OSType != linuxOS && cfg.OSType != windowsOS {
		return fmt.Errorf("unsupported OS type [%s]", cfg.OSType)
	}
	switch cfg.Flow {
	case installFlow:
		_, err := installConnector(cmgrAPI, cfg)
		return err
	case uninstallFlow:
		if cfg.ConnectorID == "" {
			return fmt.Errorf("connector ID is required for the [%s] flow", cfg.Flow)
		}
		return uninstall(cmgrAPI, cfg, connectorResources{
			ConnectorID: cfg.ConnectorID,
			PoolID:      cfg.PoolID,
			NetworkID:   cfg.NetworkID,
		})
	case installAndUninstallFlow:
		resources, err := installConnector(cmgrAPI, cfg)
		if err != nil {
			return err
		}
		return uninstall(cmgrAPI, cfg, resources)
	case installAndUpdateFlow:
		_, err := installAndUpdateConnector(cmgrAPI, cfg)
		return err
	case installAndUpdateAndUninstallFlow:
		resources, err := installAndUpdateConnector(cmgrAPI, cfg)
		if err != nil {
			return err
		}
		return uninstall(cmgrAPI, cfg, resources)
	case updateAndUninstallFlow:
		if cfg.ConnectorID == "" || cfg.NetworkID == "" {
			return fmt.Errorf("connector ID and network ID are required for the [%s] flow", cfg.Flow)
		}
		resources, err := updateConnector(cmgrAPI, cfg)
		if err != nil {
			return err
		}
		return uninstall(cmgrAPI, cfg, resources)
	default:
		return fmt.Errorf("unsupported flow [%s]", cfg.Flow)
	}
}

// connectorResources holds the identifiers of the resources a connector is built on top of.
// The pool and the network IDs are optional and are only removed when they are set.
// UpdatePoolID, when set, is a second pool created by the update flow and is deleted first during cleanup.
type connectorResources struct {
	ConnectorID  string
	PoolID       string
	NetworkID    string
	UpdatePoolID string
}

// installConnector creates a network and a pool, then installs a connector on the target machine
// and returns the identifiers of the created resources.
func installConnector(cmgrAPI *cmgr.IdsecCmgrAPI, cfg *config) (connectorResources, error) {
	network, err := cmgrAPI.Networks().Create(&networksmodels.IdsecCmgrAddNetwork{
		Name: cfg.BaseResourceName + "Network",
	})
	if err != nil {
		return connectorResources{}, fmt.Errorf("failed to create network: %w", err)
	}
	fmt.Printf("Added network: %s\n", network.NetworkID)

	pool, err := createPool(cmgrAPI, cfg.BaseResourceName+"Pool", []string{network.NetworkID})
	if err != nil {
		return connectorResources{}, err
	}

	connector, err := cmgrAPI.Connectors().Install(newInstallRequest(cfg, pool.PoolID))
	if err != nil {
		return connectorResources{}, fmt.Errorf("failed to install connector: %w", err)
	}
	fmt.Printf("Installed connector: %s\n", connector.ConnectorID)
	return connectorResources{
		ConnectorID: connector.ConnectorID,
		PoolID:      pool.PoolID,
		NetworkID:   network.NetworkID,
	}, nil
}

// newInstallRequest builds an install request holding only the parameters relevant to the
// configured OS: Windows connects over WinRM with a password and an installation path, while
// Linux connects over SSH with a private key.
func newInstallRequest(cfg *config, poolID string) *connmgmtmodels.IdsecCmgrInstall {
	if cfg.OSType == windowsOS {
		return &connmgmtmodels.IdsecCmgrInstall{
			ConnectorOS:      windowsOS,
			ConnectorPoolID:  poolID,
			TargetMachine:    cfg.WindowsMachine.TargetMachine,
			Username:         cfg.WindowsMachine.Username,
			Password:         cfg.WindowsMachine.Password,
			InstallationPath: cfg.WindowsMachine.InstallationPath,
			WinRMProtocol:    cfg.WindowsMachine.WinRMProtocol,
			CertificatePath:  cfg.WindowsMachine.CertificatePath,
			TrustCertificate: cfg.WindowsMachine.TrustCertificate,
		}
	}
	return &connmgmtmodels.IdsecCmgrInstall{
		ConnectorOS:     linuxOS,
		ConnectorPoolID: poolID,
		TargetMachine:   cfg.LinuxMachine.TargetMachine,
		Username:        cfg.LinuxMachine.Username,
		PrivateKeyPath:  cfg.LinuxMachine.PrivateKeyPath,
	}
}

// uninstall uninstalls the given connector from the configured target machine, then deletes its
// pools and network. Pools are deleted before the network because a network cannot be deleted while
// pools are still assigned to it. UpdatePoolID (when set) is deleted first, followed by PoolID.
// Both pool and network deletions are skipped when the matching ID is empty.
func uninstall(cmgrAPI *cmgr.IdsecCmgrAPI, cfg *config, resources connectorResources) error {
	if err := cmgrAPI.Connectors().Uninstall(newUninstallRequest(cfg, resources.ConnectorID)); err != nil {
		return fmt.Errorf("failed to uninstall connector [%s]: %w", resources.ConnectorID, err)
	}
	fmt.Printf("Uninstalled connector: %s\n", resources.ConnectorID)

	if resources.UpdatePoolID != "" {
		if err := cmgrAPI.Pools().Delete(&poolsmodels.IdsecCmgrDeletePool{
			PoolID: resources.UpdatePoolID,
		}); err != nil {
			return fmt.Errorf("failed to delete update pool [%s]: %w", resources.UpdatePoolID, err)
		}
		fmt.Printf("Deleted update pool: %s\n", resources.UpdatePoolID)
	}

	if resources.PoolID != "" {
		if err := cmgrAPI.Pools().Delete(&poolsmodels.IdsecCmgrDeletePool{
			PoolID: resources.PoolID,
		}); err != nil {
			return fmt.Errorf("failed to delete pool [%s]: %w", resources.PoolID, err)
		}
		fmt.Printf("Deleted pool: %s\n", resources.PoolID)
	}

	if resources.NetworkID != "" {
		if err := cmgrAPI.Networks().Delete(&networksmodels.IdsecCmgrDeleteNetwork{
			NetworkID: resources.NetworkID,
		}); err != nil {
			return fmt.Errorf("failed to delete network [%s]: %w", resources.NetworkID, err)
		}
		fmt.Printf("Deleted network: %s\n", resources.NetworkID)
	}
	return nil
}

// installAndUpdateConnector runs the update flow: it installs a connector on a first pool, then
// creates a second pool on the same network and reassigns the connector to it via Update. It
// returns all resource identifiers so the caller can clean them up with uninstall.
func installAndUpdateConnector(cmgrAPI *cmgr.IdsecCmgrAPI, cfg *config) (connectorResources, error) {
	// Step 1: create the shared network.
	network, err := cmgrAPI.Networks().Create(&networksmodels.IdsecCmgrAddNetwork{
		Name: cfg.BaseResourceName + "Network",
	})
	if err != nil {
		return connectorResources{}, fmt.Errorf("failed to create network: %w", err)
	}
	fmt.Printf("Added network: %s\n", network.NetworkID)

	// Step 2: create the first pool and install the connector on it.
	pool, err := createPool(cmgrAPI, cfg.BaseResourceName+"Pool", []string{network.NetworkID})
	if err != nil {
		return connectorResources{}, err
	}

	connector, err := cmgrAPI.Connectors().Install(newInstallRequest(cfg, pool.PoolID))
	if err != nil {
		return connectorResources{}, fmt.Errorf("failed to install connector: %w", err)
	}
	fmt.Printf("Installed connector: %s (pool: %s)\n", connector.ConnectorID, pool.PoolID)

	// Step 3: create a second pool on the same network.
	updatePool, err := createPool(cmgrAPI, cfg.BaseResourceName+"UpdatePool", []string{network.NetworkID})
	if err != nil {
		return connectorResources{}, err
	}

	// Step 4: reassign the connector to the new pool.
	updatePoolID := updatePool.PoolID
	updatedConnector, err := cmgrAPI.Connectors().Update(&connmgmtmodels.IdsecCmgrUpdate{
		ConnectorID:     connector.ConnectorID,
		ConnectorPoolID: &updatePoolID,
	})
	if err != nil {
		return connectorResources{}, fmt.Errorf("failed to update connector [%s]: %w", connector.ConnectorID, err)
	}
	fmt.Printf("Updated connector %s: pool changed to %s\n", updatedConnector.ConnectorID, updatedConnector.ConnectorPoolID)

	return connectorResources{
		ConnectorID:  connector.ConnectorID,
		PoolID:       pool.PoolID,
		NetworkID:    network.NetworkID,
		UpdatePoolID: updatePool.PoolID,
	}, nil
}

// updateConnector runs the update-and-uninstall flow against an existing connector. It expects
// config.ConnectorID and config.NetworkID to be set; config.PoolID is kept as-is for cleanup.
// A new pool is created on the existing network, the connector is reassigned to it via Update,
// and all resource identifiers are returned so the caller can run a full uninstall + cleanup.
func updateConnector(cmgrAPI *cmgr.IdsecCmgrAPI, cfg *config) (connectorResources, error) {
	// Create a new pool on the existing network.
	updatePool, err := createPool(cmgrAPI, cfg.BaseResourceName+"UpdatePool", []string{cfg.NetworkID})
	if err != nil {
		return connectorResources{}, err
	}

	// Reassign the connector to the new pool.
	updatePoolID := updatePool.PoolID
	updatedConnector, err := cmgrAPI.Connectors().Update(&connmgmtmodels.IdsecCmgrUpdate{
		ConnectorID:     cfg.ConnectorID,
		ConnectorPoolID: &updatePoolID,
	})
	if err != nil {
		return connectorResources{}, fmt.Errorf("failed to update connector [%s]: %w", cfg.ConnectorID, err)
	}
	fmt.Printf("Updated connector %s: pool changed to %s\n", updatedConnector.ConnectorID, updatedConnector.ConnectorPoolID)

	return connectorResources{
		ConnectorID:  cfg.ConnectorID,
		PoolID:       cfg.PoolID,
		NetworkID:    cfg.NetworkID,
		UpdatePoolID: updatePool.PoolID,
	}, nil
}

// createPool creates a pool with the given name assigned to the provided network IDs, logs the
// created pool ID, and returns the created pool. It returns a wrapped error on failure.
func createPool(cmgrAPI *cmgr.IdsecCmgrAPI, name string, networkIDs []string) (*poolsmodels.IdsecCmgrPool, error) {
	pool, err := cmgrAPI.Pools().Create(&poolsmodels.IdsecCmgrAddPool{
		Name:               name,
		AssignedNetworkIDs: networkIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create pool [%s]: %w", name, err)
	}
	fmt.Printf("Added pool: %s\n", pool.PoolID)
	return pool, nil
}

// newUninstallRequest builds an uninstall request holding only the parameters relevant to the
// configured OS, matching the split described in newInstallRequest.
func newUninstallRequest(cfg *config, connectorID string) *connmgmtmodels.IdsecCmgrUninstall {
	if cfg.OSType == windowsOS {
		return &connmgmtmodels.IdsecCmgrUninstall{
			ConnectorID:      connectorID,
			ConnectorOS:      windowsOS,
			TargetMachine:    cfg.WindowsMachine.TargetMachine,
			Username:         cfg.WindowsMachine.Username,
			Password:         cfg.WindowsMachine.Password,
			InstallationPath: cfg.WindowsMachine.InstallationPath,
			WinRMProtocol:    cfg.WindowsMachine.WinRMProtocol,
			CertificatePath:  cfg.WindowsMachine.CertificatePath,
			TrustCertificate: cfg.WindowsMachine.TrustCertificate,
		}
	}
	return &connmgmtmodels.IdsecCmgrUninstall{
		ConnectorID:    connectorID,
		ConnectorOS:    linuxOS,
		TargetMachine:  cfg.LinuxMachine.TargetMachine,
		Username:       cfg.LinuxMachine.Username,
		PrivateKeyPath: cfg.LinuxMachine.PrivateKeyPath,
	}
}
