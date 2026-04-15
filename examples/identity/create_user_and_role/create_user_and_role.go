package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
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
	role, err := identityAPI.Roles().Create(&rolesmodels.IdsecIdentityCreateRole{RoleName: "myrole"})
	if err != nil {
		panic(err)
	}
	user, err := identityAPI.Users().Create(&usersmodels.IdsecIdentityCreateUser{Username: "myuser"})
	if err != nil {
		panic(err)
	}
	isServiceUser := true
	isOauthClient := true
	serviceUser, err := identityAPI.Users().Create(&usersmodels.IdsecIdentityCreateUser{Username: "myserviceuser", IsServiceUser: &isServiceUser, IsOauthClient: &isOauthClient})
	if err != nil {
		panic(err)
	}
	member, err := identityAPI.Roles().AddMember(&rolesmodels.IdsecIdentityAddMemberToRole{RoleID: role.RoleID, MemberName: user.Username, MemberType: directoriesmodels.EntityTypeUser})
	if err != nil {
		panic(err)
	}
	serviceMember, err := identityAPI.Roles().AddMember(&rolesmodels.IdsecIdentityAddMemberToRole{RoleID: role.RoleID, MemberName: serviceUser.Username, MemberType: directoriesmodels.EntityTypeUser})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Member added to role: %v\n", member)
	fmt.Printf("Service Member added to role: %v\n", serviceMember)
	fmt.Printf("User: %v\n", user)
	fmt.Printf("Service User: %v\n", serviceUser)
	fmt.Printf("Role: %v\n", role)
}
