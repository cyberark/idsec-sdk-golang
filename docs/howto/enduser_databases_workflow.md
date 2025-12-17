---
title: End-user database workflow
description: End-user Database Workflow
---

# End-user database Workflow
Here is an example workflow for connecting to a database:

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
1. Get a short-lived SSO password for a database from the SIA service:
    ```shell linenums="0"
    idsec exec sia sso short-lived-password
    ```
1. Log in directly to the database:
    ```shell linenums="0"
    psql "host=mytenant.postgres.cyberark.cloud user=user@cyberark.cloud.12345@postgres@mypostgres.fqdn.com"
    ```
