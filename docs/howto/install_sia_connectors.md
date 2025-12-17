---
title: Install SIA connectors
description: Install SIA connectors
---

# Install SIA connectors
Here is an example workflow for installing a connector on a linux or windows box:

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
1. Create a network and connector pool:
    ```shell linenums="0"
    idsec exec cmgr add-network --name mynetwork
    idsec exec cmgr add-pool --name mypool --assigned-network-ids mynetwork_id
    ```
   1. Install a connector:
       * Windows:
           ```shell linenums="0"
           idsec exec sia access install-connector --connector-pool-id 89b4f0ff-9b06-445a-9ca8-4ca9a4d72e8c --username myuser --password mypassword --target-machine 1.1.1.1 --connector-os windows --connector-type ON-PREMISE
           ```
       * Linux:
           ```shell linenums="0"
           idsec exec sia access install-connector --connector-pool-id 89b4f0ff-9b06-445a-9ca8-4ca9a4d72e8c --username myuser --private-key-path /path/to/private_key.pem --target-machine 1.1.1.1 --connector-os linux --connector-type ON-PREMISE
           ```
