---
title: Environment
description: Useful environment variables for configuring the Idsec SDK.
---

# Environment

The Idsec SDK uses environment variables to configure its behavior and settings. Below are some of the key environment variables that can be set:

- `IDSEC_PROFILE`: Specifies the profile to use for authentication and service interactions. If not set, the default profile will be used.
- `IDSEC_LOG_LEVEL`: Sets the logging level for the SDK. Possible values include `DEBUG`, `INFO`, `WARNING`, `ERROR`, and `CRITICAL`. The default level is `CRITICAL`.
- `IDSEC_DISABLE_CERTIFICATE_VERIFICATION`: If set to `true`, disables SSL certificate verification for HTTPS requests. This is not recommended for production environments.
- `IDSEC_DISABLE_TELEMETRY_COLLECTION`: If set to `true`, disables telemetry data collection.
- `IDSEC_BASIC_KEYRING`: If set to `true`, uses a basic keyring for storing sensitive information instead of the system's secure storage.
- `IDSEC_KEYRING_FOLDER`: Specifies a custom folder path for the basic keyring storage when `IDSEC_BASIC_KEYRING` is enabled.
- `IDSEC_SUPPRESS_UPGRADE_CHECK`: If set to `true`, suppresses the automatic upgrade check when running Idsec commands.
- `IDSEC_PROXY_ADDRESS`: Specifies the proxy address to be used by the SDK for all requests.
- `IDSEC_PROXY_USERNAME`: Specifies the username for proxy authentication.
- `IDSEC_PROXY_PASSWORD`: Specifies the password for proxy authentication.
- `HTTP_PROXY`: Sets the HTTP proxy for all HTTP requests.
- `HTTPS_PROXY`: Sets the HTTPS proxy for all HTTPS requests.
- `NO_PROXY`: A comma-separated list of hostnames that should bypass the proxy.
