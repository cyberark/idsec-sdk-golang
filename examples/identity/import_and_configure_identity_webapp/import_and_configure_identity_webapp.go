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

	// Get the template and print it out
	template, err := identityAPI.Webapps().GetTemplate(&webappsmodels.IdsecIdentityGetWebappTemplate{
		WebappTemplateName: "Amazon AWS",
	})
	if err != nil {
		panic(err)
	}
	templateJson, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Webapp Template:\n%s\n", string(templateJson))

	// Import the template and configure with the AWS Account
	importedWebapp, err := identityAPI.Webapps().Import(&webappsmodels.IdsecIdentityImportWebapp{
		TemplateName: "Amazon AWS",
		WebappName:   common.Ptr("AWS App Normal"),
		Description:  common.Ptr("This is my imported AWS app"),
		IdsecIdentityWebappAppsConfiguration: webappsmodels.IdsecIdentityWebappAppsConfiguration{
			AdditionalIdentifierValue: common.Ptr("123456789234"),
			UserNameStrategy:          common.Ptr("Fixed"),
			Username:                  common.Ptr("awsuser"),
			Password:                  common.Ptr("mypass"),
		},
		IdsecIdentityWebappPolicyConfiguration: webappsmodels.IdsecIdentityWebappPolicyConfiguration{
			WebappLoginType:    common.Ptr("AuthenticationRule"),
			DefaultAuthProfile: common.Ptr("AlwaysAllowed"),
			AuthRules: &webappsmodels.IdsecIdentityWebappPolicyAuthRule{
				Enabled:   true,
				Type:      "RowSet",
				UniqueKey: "Condition",
				Value: []webappsmodels.IdsecIdentityWebappPolicyAuthRuleConditions{
					{
						Conditions: []webappsmodels.IdsecIdentityWebappPolicyAuthRuleCondition{
							{
								Op:   common.Ptr("OpInCorpIpRange"),
								Prop: common.Ptr("IpAddress"),
							},
						},
						ProfileId: common.Ptr("13e3bc1a-6ff7-4b7d-ae90-0ed21d3c393e"),
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	importedWebappJson, err := json.MarshalIndent(importedWebapp, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Imported Webapp:\n%s\n", string(importedWebappJson))

	// Import another template and configure with the AWS Account and Credentials from pCloud
	importedpCloudWebapp, err := identityAPI.Webapps().Import(&webappsmodels.IdsecIdentityImportWebapp{
		TemplateName: "Amazon AWS",
		WebappName:   common.Ptr("AWS App pCloud"),
		Description:  common.Ptr("This is my imported AWS app"),
		IdsecIdentityWebappAppsConfiguration: webappsmodels.IdsecIdentityWebappAppsConfiguration{
			AdditionalIdentifierValue: common.Ptr("123456789234"),
			UserNameStrategy:          common.Ptr("Fixed"),
			Safe:                      common.Ptr("mysafe"),
			AccountName:               common.Ptr("myaccount"),
			ExtAccountId:              common.Ptr("123_456"),
			IsPrivilegedApp:           common.Ptr(true),
		},
		IdsecIdentityWebappPolicyConfiguration: webappsmodels.IdsecIdentityWebappPolicyConfiguration{
			WebappLoginType:    common.Ptr("AuthenticationRule"),
			DefaultAuthProfile: common.Ptr("AlwaysAllowed"),
			AuthRules: &webappsmodels.IdsecIdentityWebappPolicyAuthRule{
				Enabled:   true,
				Type:      "RowSet",
				UniqueKey: "Condition",
				Value: []webappsmodels.IdsecIdentityWebappPolicyAuthRuleConditions{
					{
						Conditions: []webappsmodels.IdsecIdentityWebappPolicyAuthRuleCondition{
							{
								Op:   common.Ptr("OpInCorpIpRange"),
								Prop: common.Ptr("IpAddress"),
							},
						},
						ProfileId: common.Ptr("13e3bc1a-6ff7-4b7d-ae90-0ed21d3c393e"),
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	importedpCloudWebappJson, err := json.MarshalIndent(importedpCloudWebapp, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Imported pCloud Webapp:\n%s\n", string(importedpCloudWebappJson))

	// Configure permissions for Normal AWS App
	perms, err := identityAPI.Webapps().SetPermissions(&webappsmodels.IdsecIdentitySetWebappPermissions{
		WebappID: importedWebapp.WebappID,
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

	// Configure permissions for pCloud AWS App
	pCloudPerms, err := identityAPI.Webapps().SetPermissions(&webappsmodels.IdsecIdentitySetWebappPermissions{
		WebappID: importedpCloudWebapp.WebappID,
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
	pCloudPermsJson, err := json.MarshalIndent(pCloudPerms, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Set Permissions pCloud Result:\n%s\n", string(pCloudPermsJson))
}
