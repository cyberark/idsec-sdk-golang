---
title: End-user rdp workflow
description: End-user rdp Workflow
---

# End-user rdp Workflow
Here is an example workflow for connecting to a windows box using rdp:

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
1. Get a short-lived SSO RDP file or password for a windows box from the SIA service:
   * RDP file single usage for a windows box from the SIA service:
       ```shell linenums="0"
       idsec exec sia sso short-lived-rdp-file -ta targetaddress -td targetdomain -tu targetuser
       ```
   * Password for continous usage for a windows box from the SIA service:
       ```shell linenums="0"
       idsec exec sia sso short-lived-password --service DPA-RDP
       ```
1. Use the RDP file or password with mstsc or any other RDP client to connect
