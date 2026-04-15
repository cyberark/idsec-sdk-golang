package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud"
	applicationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/applications/models"

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

	// Add a new application and auth method
	pcloudAPI, err := pcloud.NewIdsecPCloudAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	application, err := pcloudAPI.Applications().Create(&applicationsmodels.IdsecPCloudCreateApplication{
		AppID:              "myapp",
		BusinessOwnerFName: "user",
		BusinessOwnerLName: "name",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Application created: %s\n", application.AppID)

	authMethod, err := pcloudAPI.Applications().CreateAuthMethod(&applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{
		AppID:     application.AppID,
		AuthType:  applicationsmodels.ApplicationAuthMethodHash,
		AuthValue: "myhash",
		Comment:   "My hash auth method",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Application Auth Method added: %s (ID: %s)\n", authMethod.AuthType, authMethod.AuthID)
}
