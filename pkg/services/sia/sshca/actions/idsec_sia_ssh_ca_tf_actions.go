package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sshcamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca/models"
)

// TerraformActionSSHPublicKeyResource is a struct that defines the SIA SSH Public Key resource action for the Idsec service for Terraform.
var TerraformActionSSHPublicKeyResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-ssh-public-key",
			ActionDescription: "The SIA SSH public key resource, manages SIA SSH CA public key installation and removal from a target machine.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"target_machine",
			"username",
		},
		SensitiveAttributes: []string{
			"password",
			"private_key_contents",
		},
		StateSchema: &sshcamodels.IdsecSIASSHPublicKeyOperationResult{},
	},
	RawStateInference: true,
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "install-public-key",
		actions.DeleteOperation: "uninstall-public-key",
	},
}
