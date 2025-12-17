---
title: Commands examples
description: Commands Examples
---

# Commands examples

This page lists some useful CLI examples.

!!! note

    You can disable certificate validation for login to an authenticator using the `--disable-certificate-verification` flag. **This option is not recommended.**

    **Useful environment variables**

    - `IDSEC_PROFILE`: Sets the profile to be used across the CLI
    - `IDSEC_DISABLE_CERTIFICATE_VERIFICATION`: Disables certificate verification for REST APIs

## Configure command example

The `configure` command works in interactive or silent mode. When using silent mode, the required parameters need to specified. Here's an example of configuring ISP in silent mode:

```bash linenums="0"
idsec configure --profile-name="PROD" --work-with-isp --isp-username="tina@cyberark.cloud.12345" --silent --allow-output
```

## Login commands example

The login command can work in interactive or silent mode. Here's an example of a silent login with the profile configured in the example above:
```bash linenums="0"
idsec login -s --isp-secret=CoolPasswordß --profile-name PROD
```

## Exec command examples

Use the `--help` flag to view all `exec` options.

### Generate a short-lived SSO password for a database connection
```shell linenums="0"
idsec exec sia sso short-lived-password
```

### Generate a short-lived SSO password for an RDP connection
```shell linenums="0"
idsec exec sia sso short-lived-password --service DPA-RDP
```

### Generate a short-lived SSO Oracle wallet for an Oracle database connection
```shell linenums="0"
idsec exec sia sso short-lived-oracle-wallet --folder ~/wallet
```

### Generate a kubectl config file
```shell linenums="0"
idsec exec sia k8s generate-kubeconfig 
```

### Generate a kubectl config file and save it in the specified path
```shell linenums="0"
idsec exec sia k8s generate-kubeconfig --folder=/Users/My.User/.kube
```

### Add SIA VM target set
```shell
idsec exec sia workspaces target-sets add-target-set --name mydomain.com --type Domain
```

### Add SIA VM secret
```shell
idsec exec sia secrets vm add-secret --secret-type ProvisionerUser --provisioner-username=myuser --provisioner-password=mypassword
```

### Generate new SSH CA key version
```shell linenums="0"
idsec exec sia ssh-ca generate-new-ca
```

### Deactivate previous SSH CA key version
```shell linenums="0"
idsec exec sia ssh-ca deactivate-previous-ca
```

### Reactivate previous SSH CA key version
```shell linenums="0"
idsec exec sia ssh-ca reactivate-previous-ca
```

### List CMGR connector pools
```shell
idsec exec cmgr list-pools
```

### Add CMGR network
```shell
idsec exec cmgr add-network --name mynetwork
```

### Add CMGR connector pool
```shell
idsec exec cmgr add-pool --name mypool --assigned-network-ids mynetwork_id
```

### Get connector installation script
```shell
idsec exec sia access connector-setup-script --connector-type ON-PREMISE --connector-os windows --connector-pool-id 588741d5-e059-479d-b4c4-3d821a87f012
```

### Install a connector on windows remotely
```shell
idsec exec sia access install-connector --connector-pool-id 89b4f0ff-9b06-445a-9ca8-4ca9a4d72e8c --username myuser --password mypassword --target-machine 1.2.3.4 --connector-os windows --connector-type ON-PREMISE
```

### Install a connector on linux with private key remotely
```shell
idsec exec sia access install-connector --connector-pool-id 89b4f0ff-9b06-445a-9ca8-4ca9a4d72e8c --username myuser --private-key-path /path/to/private_key.pem --target-machine 1.2.3.4 --connector-os linux --connector-type ON-PREMISE
```

### Uninstall a connector remotely
```shell
idsec exec sia access uninstall-connector --connector-id CMSConnector_588741d5-e059-479d-b4c4-3d821a87f012_1a8b3734-8e1d-43a3-bb99-8a587609e653 --username myuser --password mypassword --target-machine 1.2.3.4 --connector-os windows
```

### Create a pCloud Safe
```shell
idsec exec pcloud safes add-safe --safe-name=safe
```

### Create a pCloud account
```shell
idsec exec pcloud accounts add-account --name account --safe-name safe --platform-id='UnixSSH' --username root --address 1.2.3.4 --secret-type=password --secret mypass
```

### Retrieve a pCloud account credentials
```shell
idsec exec pcloud accounts get-account-credentials --account-id 11_1
```

### Create an Identity user
```shell
idsec exec identity users create-user --roles "DpaAdmin" --username "myuser"
```

### Create an Identity role
```shell
idsec exec identity roles create-role --role-name myrole
```

### List all directories identities
```shell
idsec exec identity directories list-directories-entities
```

### Add SIA database secret

```shell linenums="0"
idsec exec sia secrets db add-strong-account --store-type managed --name "my-postgres-account" --platform PostgreSQL --address "db.example.com" --username "dbuser" --port 5432 --database "mydb" --password "mypassword"
```

### Delete SIA database secret

```shell linenums="0"
idsec exec sia secrets db delete-secret --secret-name mysecret
```

### Add SIA database
```shell linenums="0"
idsec exec sia workspaces db add-database --name mydatabase --provider-engine aurora-mysql --read-write-endpoint myrds.com
```

### Delete SIA database
```shell linenums="0"
idsec exec sia workspaces db delete-database --id databaseid
```

### List all SIA Settings
```shell linenums="0"
idsec exec sia settings list-settings
```

### Get specific SIA setting
```shell linenums="0"
idsec exec sia settings adb-mfa-caching
```

### Set specific SIA setting
```shell linenums="0"
idsec exec sia settings set-rdp-mfa-caching --is-mfa-caching-enabled=true --client-ip-enforced=false
```

### Get Secrets Hub Configuration
```shell linenums="0"
idsec exec sechub configuration get-configuration
```

### Set Secrets Hub Configuration
```shell linenums="0"
idsec exec sechub configuration set-configuration --sync-settings 360
```

### Get Secrets Hub Filters
```shell linenums="0"
idsec exec sechub filters get-filters --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

### Add Secrets Hub Filter
```shell linenums="0"
idsec exec sechub filters add-filter --type "PAM_SAFE" --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667 --data-safe-name "example-safe"
```

### Delete Secrets Hub Filter
```shell linenums="0"
idsec exec sechub filters delete-filter --filter-id filter-7f3d187d-7439-407f-b968-ec27650be692 --store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

### Get Secrets Hub Scans
```shell linenums="0"
idsec exec sechub scans get-scans
```

### Trigger Secrets Hub Scan
```shell linenums="0"
idsec exec sechub scans trigger-scan --id default --secret-stores-ids store-e488dd22-a59c-418c-bbe3-3f061dd9b667 type secret-store
```

### Create Secrets Hub Secret Store
```shell linenums="0"
idsec exec sechub secret-stores create-secret-store --type AWS_ASM --description sdk-testing --name "SDK Testing" --state ENABLED --data-aws-account-alias ALIAS-NAME-EXAMPLE --data-aws-region-id us-east-1 --data-aws-account-id 123456789123 --data-aws-rolename Secrets-Hub-IAM-Role-Name-Created-For-Secrets-Hub
```

### Retrieve Secrets Hub Secret Store
```shell linenums="0"
idsec exec sechub secret-stores get-secret-store --secret-store-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

### Update Secrets Hub Secret Store
```shell linenums="0"
idsec exec sechub secret-stores update-secret-store --secret-store-id store-7f3d187d-7439-407f-b968-ec27650be692 --name "New Name" --description "Updated Description" --data-aws-account-alias "Test2"
```

### Delete Secrets Hub Secret Store
```shell linenums="0"
idsec exec sechub secret-stores delete-secret-store --secret-store-id store-fd11bc7c-22d0-4d9b-ac1b-f8458161935f
```

### Get Secrets Hub Secrets
```shell linenums="0"
idsec exec sechub secrets get-secrets
```

### Get Secrets Hub Secrets using a filter
```shell linenums="0"
idsec exec sechub secrets get-secrets-by --limit 5 --projection EXTEND --filter "name CONTAINS EXAMPLE"
```

### Get Secrets Hub Service Information
```shell linenums="0"
idsec exec sechub service-info get-service-info
```

### Get Secrets Hub Sync Policies
```shell linenums="0"
idsec exec sechub sync-policies get-sync-policies
```

### Get Secrets Hub Sync Policy
```shell linenums="0"
idsec exec sechub sync-policies get-sync-policy --policy-id policy-7f3d187d-7439-407f-b968-ec27650be692 --projection EXTEND
```

### Create Secrets Hub Sync Policy
```shell linenums="0"
idsec exec sechub sync-policies create-sync-policy --name "New Sync Policy" --description "New Sync Policy Description" --filter-type PAM_SAFE --filter-data-safe-name EXAMPLE-SAFE-NAME --source-id store-e488dd22-a59c-418c-bbe3-3f061dd12367 --target-id store-e488dd22-a59c-418c-bbe3-3f061dd9b667
```

### Delete Secrets Hub Sync Policy
```shell linenums="0"
idsec exec sechub sync-policies delete-sync-policy --policy-id policy-7f3d187d-7439-407f-b968-ec27650be692
```

### List Sessions
```shell linenums="0"
idsec exec sm list-sessions
```

### Count Sessions
```shell linenums="0"
idsec exec sm count-sessions
```

### List Sessions By Filter
```shell
idsec exec sm list-sessions-by --search "duration LE 01:00:00"
```

### Count Sessions By Filter
```shell linenums="0"
idsec exec sm count-sessions-by --search "command STARTSWITH ls"
```

### Get Session
```shell linenums="0"
idsec exec sm get-session --session-id my-id
```

### List Session Activities
```shell linenums="0"
idsec exec sm list-session-activities --session-id my-id
```

### Count Session Activities
```shell linenums="0"
idsec exec sm count-session-activities --session-id my-id
```

### List Session Activities By Filter
```shell linenums="0"
idsec exec sm list-session-activities-by --session-id my-id --command-contains "ls"
```

### Count Session Activities By Filter
```shell linenums="0"
idsec exec sm count-session-activities-by --session-id my-id --command-contains "chmod"
```

### List all UAP policies
```shell linenums="0"
idsec exec uap list-policies
```

### Delete UAP DB Policy
```shell linenums="0"
idsec exec uap db delete-policy --policy-id my-policy-id
```

### List DB Policies from UAP
```shell linenums="0"
idsec exec uap db list-policies
```

### Get DB Policy from UAP
```shell linenums="0"
idsec exec uap db policy --policy-id my-policy-id
```

### Add UAP DB Policy
```shell linenums="0"
idsec exec uap db add-policy --request-file /path/to/policy-request.json
```

### List UAP SCA Policies
```shell linenums="0"
idsec exec uap sca list-policies
```

### Get UAP SCA Policy
```shell linenums="0"
idsec exec uap sca policy --policy-id my-policy-id
```

### Add UAP SCA Policy
```shell linenums="0"
idsec exec uap sca add-policy --request-file /path/to/policy-request.json
```

### Delete UAP SCA Policy
```shell linenums="0"
idsec exec uap sca delete-policy --policy-id my-policy-id
```

### List VM Policies from UAP
```shell
idsec exec uap vm list-policies
```

### Get VM Policy from UAP
```shell
idsec exec uap vm policy --policy-id my-policy-id
```

### Delete VM Policy from UAP
```shell
idsec exec uap vm delete-policy --policy-id my-policy-id
```

### Connect to MySQL ZSP with the mysql cli via Idsec CLI
```shell linenums="0"
idsec exec sia db mysql --target-address myaddress.com
```

### Connect to PostgreSQL Vaulted with the psql cli via Idsec CLI
```shell linenums="0"
idsec exec sia db psql --target-address myaddress.com --target-user myuser
```

### Generate a connection string alias for a given raw connection string
```shell linenums="0"
idsec exec sia shortened-connection-string generate --raw-connection-string=jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639
```

### Install SIA SSH public key on a target machine
```shell linenums="0"
idsec exec sia ssh-ca install-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Remove SIA SSH public key from a target machine
```shell linenums="0"
idsec exec sia ssh-ca uninstall-public-key --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Check if SIA SSH public key is installed on a target machine
```shell linenums="0"
idsec exec sia ssh-ca is-public-key-installed --private-key-path /path/to/key.pem --target-machine 1.1.1.1 --username user
```

### Add a SIA certificate
```shell linenums="0"
idsec exec sia certificates add-certificate --cert-name name --cert-type PEM --file /path/to/cert.crt
```

### Update a SIA certificate
```shell linenums="0"
idsec exec sia certificates update-certificate --certificate-id cert-id --cert-name new-name --file /path/to/new-cert.crt
```

### List all SIA certificates
```shell linenums="0"
idsec exec sia certificates list-certificates
```

### Import a pCloud Platform
```shell linenums="0"
idsec exec pcloud platforms import-platform --platform-zip-path /path/to/zip
```

### Import a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud platforms import-target-platform --platform-zip-path /path/to/zip
```

### Export a pCloud Platform
```shell linenums="0"
idsec exec pcloud platforms export-platform --platform-id myid --output-folder /path/to/folder
```

### Export a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud platforms export-target-platform --target-platform-id 123 --output-folder /path/to/folder
```

### List pCloud Target Platforms
```shell linenums="0"
idsec exec pcloud platforms list-target-platforms
```

### Activate a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud platforms activate-target-platform --target-platform-id 123
```

### Deactivate a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud platforms deactivate-target-platform --target-platform-id 123
```

### Delete a pCloud Target Platform
```shell linenums="0"
idsec exec pcloud platforms delete-target-platform --target-platform-id 123
```
