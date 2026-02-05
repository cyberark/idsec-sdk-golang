package config

import (
	"net/http"
	"net/url"
)

// ConfigureProxy configures the proxy URL for the given HTTP request
func ConfigureProxy(req *http.Request) (*url.URL, error) {
	// Resolve proxy address, prioritizing the explicit proxy address if set, falling back to environment variables
	var proxyURL *url.URL
	var err error
	if ProxyAddress() != "" {
		// Ignore errors even if the proxy address is invalid
		// As we will fall back to environment variables in that case
		proxyURL, _ = url.Parse(ProxyAddress())
	}
	if proxyURL == nil {
		proxyURL, err = http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, err
		}
	}

	// Configure credentials for proxy if set
	if proxyURL != nil {
		if ProxyUsername() != "" && ProxyPassword() != "" {
			proxyURL.User = url.UserPassword(ProxyUsername(), ProxyPassword())
		}
	}
	return proxyURL, nil
}
