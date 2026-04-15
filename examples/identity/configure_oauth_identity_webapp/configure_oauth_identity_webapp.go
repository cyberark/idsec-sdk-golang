package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
	webappsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/webapps/models"
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
	// Import the OAuth Server template and configure it as an example
	app, err := identityAPI.Webapps().Import(
		&webappsmodels.IdsecIdentityImportWebapp{
			IdsecIdentityWebappAppsConfiguration: webappsmodels.IdsecIdentityWebappAppsConfiguration{
				OAuthProfile: &webappsmodels.IdsecIdentityWebappOAuthProfile{ // #nosec G101
					AllowedAuth: []string{
						"ClientCreds",
					},
					Audience: common.Ptr("company://audience"),
					Issuer:   common.Ptr("mycompany.com"),
					KnownScopes: []webappsmodels.IdsecIdentityWebappOAuthScope{
						{
							Scope:       "scope1",
							Description: "Scope 1",
						},
					},
					TokenType:           "JwtRS256",
					TokenLifetimeString: "0.05:00:00",
				},
			},
			TemplateName: "OAuth2Server",
			WebappName:   common.Ptr("OAuth App"),
			ServiceName:  common.Ptr("app_id"),
		},
	)
	if err != nil {
		panic(err)
	}
	appJson, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Imported App Result:\n%s\n", string(appJson))

	// Configure permissions
	perms, err := identityAPI.Webapps().SetPermissions(&webappsmodels.IdsecIdentitySetWebappPermissions{
		WebappID: app.WebappID,
		Grants: []webappsmodels.IdsecIdentityWebappGrant{
			{
				Principal:     "user@cyberark.cloud.12345",
				PrincipalType: "User",
				Rights: []string{
					webappsmodels.GrantRightAdmin,
					webappsmodels.GrantRightGrant,
					webappsmodels.GrantRightView,
					webappsmodels.GrantRightViewDetail,
					webappsmodels.GrantRightExecute,
					webappsmodels.GrantRightAutomatic,
					webappsmodels.GrantRightDelete,
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	permsJson, err := json.MarshalIndent(perms, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Set Permissions Result:\n%s\n", string(permsJson))
}
