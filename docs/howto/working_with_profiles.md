---
title: Work with profiles
description: Working With Profiles
---

# Work with profiles
Profiles define authentication methods for users. The SDK uses profiles to load authentication configuration for service interactions.

You can specify which profile the SDK uses by setting the `IDSEC_PROFILE` environment variable.

Profiles are stored as JSON files in the `$HOME/.idsec/profiles` folder.

!!! note

    When there are multiple profiles configured but a profile is not specified via the `IDSEC_PROFILE` environment variable, the default `idsec` profile is used.

Here is an example profile file:

``` json
{
    "profile_name": "idsec",
    "profile_description": "Default Idsec Profile",
    "auth_profiles": {
        "isp": {
            "username": "tina@cyberark.cloud.1234567",
            "auth_method": "identity",
            "auth_method_settings": {
                "identity_mfa_method": "email",
                "identity_mfa_interactive": true,
                "identity_application": null,
                "identity_url": null
            }
        }
    }
}
```

You can create, modify, and delete profiles directly in the `$HOME/.idsec/profiles` folder. For CLI-based profile configuration, see the [Idsec CLI documentation](https://github.com/cyberark/idsec-cli-golang).
