---
title: End-user ssh workflow
description: End-user ssh Workflow
---

# End-user SSH workflow
Here is an example workflow for connecting to a linux box using SSH:

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
1. Get a short-lived SSH private key for a linux box from the SIA service:
    ```shell linenums="0"
    idsec exec sia sso short-lived-ssh-key
    ```
1. Log in directly to the linux box:
    ```shell linenums="0"
    ssh -i ~/.ssh/sia_ssh_key.pem myuser@suffix@targetuser@targetaddress@sia_proxy
    ```
