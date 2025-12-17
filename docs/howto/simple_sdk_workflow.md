---
title: Simple SDK Workflow
description: Simple SDK Workflow
---

# Simple SDK Workflow
Here's an example tha shows how to generate a short-lived password for an SIA connection.

## Short lived password example
```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso"
	"os"
)

func main() {
	// Perform authentication using IdsecISPAuth to the platform
	// Firstly, create an ISP authentication class
	// Secondly, perform the authentication
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

	// Create an SSO service from the authenticator above
	ssoService, err := sso.NewIdsecSIASSOService(ispAuth)
	if err != nil {
		panic(err)
	}

	// Generate a short-lived password
	ssoPassword, err := ssoService.ShortLivedPassword(
		&ssomodels.IdsecSIASSOGetShortLivedPassword{},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", ssoPassword)
}
```

## Code description

The code example does this:

1. Imports the required packages:
    * the `authmodels` package is used to authenticate to the platform
	* the `ssomodels` package is used to generate a short-lived password.
1. Creates an instance of `IdsecISPAuth`, which calls the `Authenticate` method to authenticate to the platform. The `Authenticate` method takes these parameters: username, authentication method, authentication method settings, and password.
1. Creates an instance of `IdsecSIASSOService` using the `ispAuth` authentication instance. The instance is named `ssoService`, and it is used to generate a short-lived password.
1. Calls `ssoService` instance's `ShortLivedPassword` method to created a short-lived password, which is printed in the console.
