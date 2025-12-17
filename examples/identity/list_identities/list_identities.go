package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"

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

	// List all identities
	identityAPI, err := identity.NewIdsecIdentityAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	identitiesChan, err := identityAPI.Directories().ListDirectoriesEntities(&directoriesmodels.IdsecIdentityListDirectoriesEntities{})
	if err != nil {
		panic(err)
	}
	for loadedIdentity := range identitiesChan {
		fmt.Printf("Identity: %v\n", loadedIdentity)
	}
}
