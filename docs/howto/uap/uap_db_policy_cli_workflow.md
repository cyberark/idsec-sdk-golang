---
title: UAP database policy CLI workflow
description: Creating a UAP DB Policy using Idsec CLI
---

# UAP database policy CLI workflow
Here is an example workflow for adding a UAP DB policy alongside all needed assets via the CLI:

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
1. Add SIA DB User Secret
    ```shell
    idsec exec sia secrets db add-strong-account --store-type managed --name "my-postgres-account" --platform PostgreSQL --address "db.example.com" --username "dbuser" --port 5432 --database "mydb" --password "mypassword"
    ```
1. Add SIA Database
    ```shell
    idsec exec sia workspaces db add-database \
      --name mydomain.com \
      --provider-engine postgres-sh \
      --read-write-endpoint myendpoint.mydomain.com \
      --secret-id <SECRET_ID_FROM_PREVIOUS_STEP>
    ```
1. Create UAP DB Policy using a defined json file
    ```json
    {
      "metadata": {
        "name": "Cool Policy",
        "description": "Cool Policy Description",
        "status": { "status": "ACTIVE" },
        "timeFrame": { "fromTime": null, "toTime": null },
        "policyEntitlement": {
          "targetCategory": "DB",
          "locationType": "FQDN_IP",
          "policyType": "RECURRING"
        },
        "policyTags": ["cool_tag", "cool_tag2"],
        "timeZone": "Asia/Jerusalem"
      },
      "principals": [
        {
          "id": "principal_id",
          "name": "tester@cyberark.cloud",
          "sourceDirectoryName": "CyberArk Cloud Directory",
          "sourceDirectoryId": "source_directory_id",
          "type": "USER"
        }
      ],
      "conditions": {
        "accessWindow": {
          "daysOfTheWeek": [0, 1, 2, 3, 4, 5, 6],
          "fromHour": "05:00",
          "toHour": "23:59"
        },
        "maxSessionDuration": 2,
        "idleTime": 1
      },
      "targets": {
        "FQDN_IP": {
          "instances": [
            {
              "instanceName": "Mongo-atlas_ephemeral_user",
              "instanceType": "Mongo",
              "instanceId": "1234",
              "authenticationMethod": "MONGO_AUTH",
              "mongoAuthProfile": {
                "globalBuiltinRoles": ["readWriteAnyDatabase"],
                "databaseBuiltinRoles": {
                  "mydb1": ["userAdmin"],
                  "mydb2": ["dbAdmin"]
                },
                "databaseCustomRoles": {
                  "mydb1": ["myCoolRole"]
                }
              }
            }
          ]
        }
      }
    }
    ```

    ```shell
    idsec exec --request-file /path/to/policy-request.json uap db add-policy
    ```
