package actions

import siasshca "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca/models"

// ActionToSchemaMap is a map that defines the mapping between ssh-ca action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"generate-new-ca":         nil,
	"deactivate-previous-ca":  nil,
	"reactivate-previous-ca":  nil,
	"public-key":              &siasshca.IdsecSIAGetSSHPublicKey{},
	"public-key-script":       &siasshca.IdsecSIAGetSSHPublicKeyScript{},
	"install-public-key":      &siasshca.IdsecSIAInstallSSHPublicKey{},
	"uninstall-public-key":    &siasshca.IdsecSIAUninstallSSHPublicKey{},
	"is-public-key-installed": &siasshca.IdsecSIAIsSSHPublicKeyInstalled{},
}
