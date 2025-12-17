---
title: Work with profiles
description: Working With Profiles
---

# Work with profiles
Profiles define authentication methods for users. They are used with the CLI and, to a lesser extent, the SDK. Different profiles can be created and configured via the Idsec `configure` command.

You can specify which profile a command uses with the `--profile-name` flag or setting the `IDSEC_PROFILE` environment variable.

Profiles are stored as JSON files in the `$HOME/.idsec_profiles` folder.

!!! note

    When there are multiple profiles configured but a profile is not specified in the command (via  
    `--profile-name`) or with the `IDSEC_PROFILE` environment variable, the default `idsec` profile is used.


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

As well as using the CLI to manage profiles, you can create, modify, and delete profiles directly in the `$HOME/.idsec_profiles` folder.
