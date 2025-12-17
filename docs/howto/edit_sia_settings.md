---
title: Edit SIA Settings
description: Edit SIA Settings
---

# Edit SIA Settings
Here is an example workflow for editing SIA settings:

1. Install Idsec SDK with your artifactory credentials:
   ```shell linenums="0"
   export GOPRIVATE=1
   git config --global url.\"https://<artifactoryUser>:<artifactoryToken>@github.com\".insteadOf \"https://github.com\"
   go install github.com/cyberark/idsec-sdk-golang/cmd/idsec@latest
   ```
   Make sure that the PATH environment variable points to the Go binary. For example:
   ```shell linenums="0"
   export PATH=$PATH:$(go env GOPATH)/bin
   ```
1. Create a profile:
    * Interactively:
        ```shell linenums="0"
        idsec configure
        ```
    * Silently:
        ```shell linenums="0"
        idsec configure --silent --work-with-isp --isp-username myuser
        ```
1. Log in to Idsec:
    ```shell linenums="0"
    idsec login --silent --isp-secret <my-idsec-secret>
    ```
1. Retrieve all settings:
    ```shell linenums="0"
    idsec exec sia settings list-settings
    ```
1. Edit a specific setting:
    ```shell linenums="0"
    idsec exec sia settings set-rdp-mfa-caching --is-mfa-caching-enabled=true --client-ip-enforced=false
    ```
