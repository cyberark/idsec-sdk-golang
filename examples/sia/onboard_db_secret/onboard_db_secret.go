package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	dbsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/db/models"

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

	// Add a DB secret
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	account, err := siaAPI.SecretsDB().AddStrongAccount(
		&dbsecretsmodels.IdsecSIADBAddStrongAccount{
			StoreType: "managed",
			Platform:  "PostgreSQL",
			Name:      "MyCoolAccount",
			Username:  "CoolUser",
			Password:  "CoolPassword",
			Address:   "myrds.com",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Account ID:", account.ID)
}
