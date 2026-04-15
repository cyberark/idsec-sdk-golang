package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"

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

	identityAPI, err := identity.NewIdsecIdentityAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	user, err := identityAPI.Users().Create(&usersmodels.IdsecIdentityCreateUser{Username: "myuser"})
	if err != nil {
		panic(err)
	}
	userSchema, err := identityAPI.Users().UpsertAttributesSchema(&usersmodels.IdsecIdentityUpsertUserAttributesSchema{
		Columns: []usersmodels.IdsecIdentityUserAttributesSchemaColumn{
			{Name: "department_attr1", Type: "Text", Description: "Department attribute 1"},
			{Name: "location_attr2", Type: "Text", Description: "Location attribute 2"},
		},
	})
	if err != nil {
		panic(err)
	}
	userAttributes, err := identityAPI.Users().UpsertAttributes(&usersmodels.IdsecIdentityUpsertUserAttributes{
		UserID: user.UserID,
		Attributes: map[string]string{
			"department_attr1": "engineering",
			"location_attr2":   "NYC",
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("User Attributes for user %s: %+v\n", user.Username, userAttributes.Attributes)
	fmt.Printf("User: %v\n", user)
	fmt.Printf("User Attributes Schema: %v\n", userSchema)
}
