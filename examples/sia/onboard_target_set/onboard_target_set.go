package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	vmsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/models"
	targetsetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/targetsets/models"

	"os"
)

func main() {
	// Perform authentication using IdsecISPAuth to the platform
	// First, create an ISP authentication class
	// Afterwards, perform the authentication
	ispAuth := auth.NewIdsecISPAuth(false)
	_, err := ispAuth.Authenticate(
		nil,
		&authmodels.IdsecAuthProfile{
			Username:           "user@cyberark.cloud.12345",
			AuthMethod:         authmodels.Identity,
			AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{},
		},
		&authmodels.IdsecSecret{
			Secret: os.Getenv("IDSEC_SECRET"),
		},
		false,
		false,
	)
	if err != nil {
		panic(err)
	}

	// Add a VM secret
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	secret, err := siaAPI.SecretsVM().AddSecret(
		&vmsecretsmodels.IdsecSIAVMAddSecret{
			SecretType:          "ProvisionerUser",
			ProvisionerUsername: "CoolUser",
			ProvisionerPassword: "CoolPassword",
		},
	)
	if err != nil {
		panic(err)
	}
	// Add VM target set
	targetSet, err := siaAPI.WorkspacesTargetSets().AddTargetSet(
		&targetsetsmodels.IdsecSIAAddTargetSet{
			Name:       "mydomain.com",
			Type:       "Domain",
			SecretID:   secret.SecretID,
			SecretType: secret.SecretType,
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Target set %s created\n", targetSet.ID)
}
