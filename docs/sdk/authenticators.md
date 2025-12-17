---
title: Authenticators
description: Authenticators
---

# Authenticators

An authenticator provides the ability to authenticate to a CyberArk Identity Security Platform (ISP) resource. The authentication is based on authentication profiles, where the authentication profile defines the authentication method and its associated settings.

Here's an example of how to initialize and use an authenticator:

```go
package main

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
)

func main() {
	ispAuth := auth.NewIdsecISPAuth(false)
}
```

!!! note

    When you call the constructor, you can determine whether or not the authentication credentials are cached.

Authenticators have a base authenticate method that receives a profile as an input and returns an auth token. Additionally, the IdsecISPAuth class exposes functions to retrieve a profile's authentication methods and settings. Although the returned token can be used as a return value, it can normally be ignored as it is saved internally.

These are the different types of authenticator types and auth methods:

## Authenticator types

Currently, IdsecISPAuth is the only supported authenticator type, which is derived from the IdsecAuth interface and accepts the `Identity` (default) and `IdentityServiceUser` auth methods.

## Auth methods

- <b>Identity</b> (`identity`) - Identity authentication to a tenant or to an application within the Identity tenant, used with the IdentityIdsecAuthMethodSettings class
- <b>IdentityServiceUser</b> (`identity_service_user`) - Identity authentication with a service user, used with IdentityServiceUserIdsecAuthMethodSettings class
- <b>Direct</b> (`direct`) - Direct authentication to an endpoint, used with the DirectIdsecAuthMethodSettings class
- <b>Default</b> (`default`) - Default authenticator auth method for the authenticator
- <b>Other</b> (`other`) - For custom implementations

See [idsec_auth_method.go](https://github.com/cyberark/idsec-sdk-golang/blob/main/pkg/models/auth/idsec_auth_method.go){:target="_blank" rel="noopener"} for more information about auth methods.

## SDK authenticate example

Here is an example authentication flow that implements the IdsecISPAuth class:

```go
package main

import (
	"fmt"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
	"os"
)

func main() {
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
}
```

The example above initializes an instance of the IdsecISPAuth class and authenticates to the specified ISP tenant, using the `Identity` authentication type with the provided username and password.

The `authenticate` method returns a token, which can usually be ignored because it is stored internally.

After authenticating, the authenticator can be used to access the required services.
