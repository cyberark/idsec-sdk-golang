package actions

import accessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access/models"

// ActionToSchemaMap is a map that defines the mapping between Access action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"connector-setup-script":            &accessmodels.IdsecSIAGetConnectorSetupScript{},
	"install-connector":                 &accessmodels.IdsecSIAInstallConnector{},
	"uninstall-connector":               &accessmodels.IdsecSIAUninstallConnector{},
	"test-connector-reachability":       &accessmodels.IdsecSIATestConnectorReachability{},
	"delete-connector":                  &accessmodels.IdsecSIADeleteConnector{},
	"list-connectors":                   nil,
	"update-connector-maintenance-mode": &accessmodels.IdsecSIAMaintenanceConnector{},
}
