---
title: Proxy
description: Configuring a proxy with Idsec SDK.
---

# Proxy

The Idsec SDK consumes many different API's from the ISP backend, for authentication or for actual services usage

To configure a proxy to work with the above, one can do it in a few ways:

1. Set the `HTTPS_PROXY` environment variable to the proxy URL. This will make all HTTPS requests go through the proxy.
2. Set the `HTTP_PROXY` environment variable to the proxy URL. This will make all HTTP requests go through the proxy.
3. Set the `NO_PROXY` environment variable to a comma-separated list of hostnames that should bypass the proxy.
4. Set the `IDSEC_PROXY_ADDRESS` environment variable to the proxy URL. This will make all requests from the Idsec SDK go through the proxy, this overrides the `HTTP_PROXY` and `HTTPS_PROXY` settings.
5. Configure the proxy settings in the code by using the `SetProxyAddress` method of the SDK.

# Authentication

If the proxy requires authentication, you can set the `IDSEC_PROXY_USERNAME` and `IDSEC_PROXY_PASSWORD` environment variables to the appropriate values. This will allow the Idsec SDK to authenticate with the proxy when making requests.
