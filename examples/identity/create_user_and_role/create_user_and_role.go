package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
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

	// Add role and user
	identityAPI, err := identity.NewIdsecIdentityAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	role, err := identityAPI.Roles().CreateRole(&rolesmodels.IdsecIdentityCreateRole{RoleName: "myrole"})
	if err != nil {
		panic(err)
	}
	user, err := identityAPI.Users().CreateUser(&usersmodels.IdsecIdentityCreateUser{Username: "myuser", Roles: []string{role.RoleName}})
	if err != nil {
		panic(err)
	}
	fmt.Printf("User: %v\n", user)
	fmt.Printf("Role: %v\n", role)
}
