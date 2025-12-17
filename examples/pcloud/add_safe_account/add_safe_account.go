package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"

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

	// Add a new safe and account
	pcloudAPI, err := pcloud.NewIdsecPCloudAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	safe, err := pcloudAPI.Safes().AddSafe(&safesmodels.IdsecPCloudAddSafe{
		SafeName: "mysafe",
	})
	if err != nil {
		panic(err)
	}
	account, err := pcloudAPI.Accounts().AddAccount(&accountsmodels.IdsecPCloudAddAccount{
		SafeName:   safe.SafeName,
		Secret:     "mysecret",
		Username:   "myuser",
		Address:    "myaddr.com",
		PlatformID: "UnixSSH",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Safe added: %s\n", safe.SafeName)
	fmt.Printf("Account added: %s\n", account.AccountID)
}
