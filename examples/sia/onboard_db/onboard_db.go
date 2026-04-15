package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	dbstrongaccountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/dbstrongaccounts/models"
	workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacesdb/models"

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
	account, err := siaAPI.DBStrongAccounts().Create(
		&dbstrongaccountsmodels.IdsecSIADBAddStrongAccount{
			StoreType: "managed",
			Platform:  "MySQL",
			Name:      "MyCoolAccount",
			Username:  "CoolUser",
			Password:  "CoolPassword",
			Address:   "myrds.com",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Strong Account ID:", account.StrongAccountID)

	// Add the database with the created account
	database, err := siaAPI.WorkspacesDB().CreateTarget(
		&workspacesdbmodels.IdsecSIADBAddDatabaseTarget{
			Name:                     "MyDatabase",
			ProviderEngine:           workspacesdbmodels.EngineTypeMySQLAWSAurora,
			ReadWriteEndpoint:        "myrds.com",
			SecretID:                 account.StrongAccountID,
			Platform:                 commonmodels.WorkspaceTypeAWS,
			ConfiguredAuthMethodType: workspacesdbmodels.LocalEphemeralUser,
		},
	)

	if err != nil {
		panic(err)
	}
	fmt.Printf("Database: %v\n", database)
}
