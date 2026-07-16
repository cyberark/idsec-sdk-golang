// Package common provides shared utilities and types for the IDSEC SDK.
//
// This package implements a comprehensive HTTP client with features like:
// - Authentication support (token-based, basic auth)
// - Cookie management with persistent storage
// - Automatic token refresh capabilities
// - Request/response logging
// - TLS configuration options
//
// The IdsecClient is the primary interface for making HTTP requests to Idsec services,
// providing a consistent and feature-rich HTTP client implementation.
package common

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"path/filepath"

	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

// Number of retry attempts for token refresh operations.
const (
	refreshRetryCount = 3
)

// Defaults governing automatic retry of transient failures. These cover
// connection-close style transport errors (for example a bare "EOF" produced
// when an idle keep-alive connection is reused after the server or an
// intervening load balancer has already closed it) and HTTP 429 rate-limit
// responses. Both classes indicate the request was not durably processed, so
// retrying with backoff is safe even for non-idempotent methods.
const (
	// defaultTransientRetryCount is the number of additional attempts made when
	// a request fails with a transient transport error or a 429 response.
	defaultTransientRetryCount = 3
	// defaultTransientRetryBaseWait is the base backoff applied before the first
	// retry; subsequent retries grow exponentially up to defaultTransientRetryMaxWait.
	defaultTransientRetryBaseWait = 500 * time.Millisecond
	// defaultTransientRetryMaxWait caps the exponential backoff between retries.
	defaultTransientRetryMaxWait = 10 * time.Second
)

// IdsecAuthorizationTokenTypeRaw is the tokenType argument for UpdateToken that sets
// the configured auth header to the token string only, with no scheme prefix (no
// "Bearer " prefix). CyberArk PAS/PVWA REST expects the Logon session token as the
// entire Authorization header value per product documentation.
const IdsecAuthorizationTokenTypeRaw = "Raw"

// cookieJSON represents the JSON serializable format of an HTTP cookie.
//
// This structure is used for marshaling and unmarshaling HTTP cookies
// to and from JSON format, enabling persistent cookie storage and
// session management across client instances.
type cookieJSON struct {
	Name        string        `json:"name"`
	Value       string        `json:"value"`
	Quoted      bool          `json:"quoted"`
	Path        string        `json:"path,omitempty"`
	Domain      string        `json:"domain,omitempty"`
	Expires     time.Time     `json:"expires,omitempty"`
	RawExpires  string        `json:"raw_expires,omitempty"`
	MaxAge      int           `json:"max_age,omitempty"`
	Secure      bool          `json:"secure,omitempty"`
	HTTPOnly    bool          `json:"http_only,omitempty"`
	SameSite    http.SameSite `json:"same_site,omitempty"`
	Partitioned bool          `json:"partitioned,omitempty"`
	Raw         string        `json:"raw,omitempty"`
	Unparsed    []string      `json:"unparsed,omitempty"`
}

// IdsecClient provides a comprehensive HTTP client for interacting with Idsec services.
//
// IdsecClient wraps the standard Go HTTP client with additional features specifically
// designed for Idsec service interactions. It handles authentication, cookie management,
// request logging, and automatic token refresh capabilities.
//
// Key features:
// - Token-based and basic authentication support
// - Persistent cookie storage with JSON serialization
// - Automatic retry with token refresh on 401 responses
// - Configurable headers for all requests
// - Request/response logging with timing information
// - TLS configuration support
//
// The client maintains state including authentication tokens, custom headers,
// and cookie storage, making it suitable for session-based interactions
// with Idsec services.
type IdsecClient struct {
	BaseURL                   string
	token                     string
	tokenType                 string
	authHeaderName            string
	client                    *http.Client
	headers                   map[string]string
	cookieJar                 *cookiejar.Jar
	refreshConnectionCallback func(*IdsecClient) error
	telemetry                 telemetry.IdsecTelemetry
	owningService             string
	logger                    *IdsecLogger
	retryCallback             func(*IdsecClient, *http.Request, *http.Response) bool
	retryCount                int
	transientRetryCount       int
	transientRetryBaseWait    time.Duration
	transientRetryMaxWait     time.Duration
}

// MarshalCookies serializes a cookie jar into a JSON byte array.
//
// This function converts all cookies from a cookiejar.Jar into a JSON-serializable
// format, enabling persistent storage of cookie state. The resulting byte array
// can be stored to disk or transmitted over networks for session persistence.
//
// Note: This implementation uses the AllCookies() method from persistent-cookiejar
// which provides direct access to all stored cookies.
//
// Parameters:
//   - cookieJar: The cookie jar containing cookies to be marshaled
//
// Returns the JSON byte array representation of all cookies, or an error
// if JSON marshaling fails.
//
// Example:
//
//	cookieData, err := MarshalCookies(client.GetCookieJar())
//	if err != nil {
//	    // handle error
//	}
//	// Save cookieData to file or database
func MarshalCookies(cookieJar *cookiejar.Jar) ([]byte, error) {
	jsonCookies := make([]cookieJSON, len(cookieJar.AllCookies()))
	for i, c := range cookieJar.AllCookies() {
		jsonCookies[i] = cookieJSON{
			Name:        c.Name,
			Value:       c.Value,
			Quoted:      c.Quoted,
			Path:        c.Path,
			Domain:      c.Domain,
			Expires:     c.Expires,
			RawExpires:  c.RawExpires,
			MaxAge:      c.MaxAge,
			Secure:      c.Secure,
			HTTPOnly:    c.HttpOnly,
			SameSite:    c.SameSite,
			Partitioned: c.Partitioned,
			Raw:         c.Raw,
			Unparsed:    c.Unparsed,
		}
	}
	cookiesBytes, err := json.Marshal(jsonCookies)
	if err != nil {
		return nil, err
	}
	return cookiesBytes, nil
}

// UnmarshalCookies deserializes a JSON byte array into a cookie jar.
//
// This function takes a JSON byte array (typically created by MarshalCookies)
// and populates the provided cookie jar with the deserialized cookies.
// The cookies are organized by URL and properly set in the jar for use
// in subsequent HTTP requests.
//
// Parameters:
//   - cookies: JSON byte array containing serialized cookie data
//   - cookieJar: The cookie jar to populate with deserialized cookies
//
// Returns an error if JSON unmarshaling fails or if URL parsing encounters
// invalid cookie data.
//
// Example:
//
//	err := UnmarshalCookies(savedCookieData, client.GetCookieJar())
//	if err != nil {
//	    // handle error
//	}
//	// Cookie jar now contains restored cookies
func UnmarshalCookies(cookies []byte, cookieJar *cookiejar.Jar) error {
	var jsonCookies []cookieJSON
	if err := json.Unmarshal(cookies, &jsonCookies); err != nil {
		return err
	}
	allCookies := make([]*http.Cookie, len(jsonCookies))
	for i, c := range jsonCookies {
		allCookies[i] = &http.Cookie{
			Name:        c.Name,
			Value:       c.Value,
			Quoted:      c.Quoted,
			Path:        c.Path,
			Domain:      c.Domain,
			Expires:     c.Expires,
			RawExpires:  c.RawExpires,
			MaxAge:      c.MaxAge,
			Secure:      c.Secure,
			HttpOnly:    c.HTTPOnly,
			SameSite:    c.SameSite,
			Partitioned: c.Partitioned,
			Raw:         c.Raw,
			Unparsed:    c.Unparsed,
		}
	}
	cookieGroups := make(map[string][]*http.Cookie)
	for _, cookie := range allCookies {
		urlKey := fmt.Sprintf("https://%s%s", cookie.Domain, cookie.Path)
		cookieGroups[urlKey] = append(cookieGroups[urlKey], cookie)
	}
	for urlKey, cookiesGroup := range cookieGroups {
		parsedURL, err := url.Parse(urlKey)
		if err != nil {
			return fmt.Errorf("failed to parse URL %s: %w", urlKey, err)
		}
		cookieJar.SetCookies(parsedURL, cookiesGroup)
	}
	return nil
}

// NewSimpleIdsecClient creates a basic IdsecClient instance with minimal configuration.
//
// This is a convenience constructor for creating an IdsecClient with only a base URL.
// It uses default values for all other parameters (no authentication, new cookie jar,
// no refresh callback). This is suitable for simple use cases or as a starting point
// for further configuration.
//
// Parameters:
//   - baseURL: The base URL for the Idsec service (HTTPS prefix will be added if missing)
//
// Returns a configured IdsecClient instance ready for basic HTTP operations.
//
// Example:
//
//	client := NewSimpleIdsecClient("api.example.com")
//	response, err := client.Get(ctx, "/users", nil)
func NewSimpleIdsecClient(baseURL string) *IdsecClient {
	return NewIdsecClient(baseURL, "", "", "Authorization", nil, nil, "", false)
}

// NewIdsecClient creates a new IdsecClient instance with comprehensive configuration options.
//
// This is the primary constructor for IdsecClient, allowing full customization of
// authentication, cookie management, and refresh behavior. The client will automatically
// add HTTPS prefix to the base URL if not present and initialize a new cookie jar
// if none is provided.
//
// Parameters:
//   - baseURL: The base URL for the Idsec service
//   - token: Authentication token (empty string for no authentication)
//   - tokenType: Type of token ("Bearer", "Basic", etc.)
//   - authHeaderName: Name of the authorization header (e.g., "Authorization")
//   - cookieJar: Cookie jar for session management (nil for new jar)
//   - refreshCallback: Function to call for token refresh on 401 responses (nil to disable)
//   - owningService: Name of the service using this client (for logging/telemetry)
//   - enableTelemetry: Flag to enable telemetry collection
//
// Returns a fully configured IdsecClient instance.
//
// Example:
//
//	jar, _ := cookiejar.New(nil)
//	client := NewIdsecClient(
//	    "https://api.example.com",
//	    "abc123",
//	    "Bearer",
//	    "Authorization",
//	    jar,
//	    func(c *IdsecClient) error {
//	        // Token refresh logic
//	        return nil
//	    },
//	)
func NewIdsecClient(
	baseURL string,
	token string,
	tokenType string,
	authHeaderName string,
	cookieJar *cookiejar.Jar,
	refreshCallback func(*IdsecClient) error,
	owningService string,
	enableTelemetry bool,
) *IdsecClient {
	var err error
	if baseURL != "" && !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	if cookieJar == nil {
		// Make sure to remove corrupted cookie jar lock file
		_ = os.Remove(fmt.Sprintf("%s.lock", cookiejar.DefaultCookieFile()))
		cookieJar, err = cookiejar.New(nil)
		if err != nil {
			// Remove jar file and try again
			_ = os.Remove(cookiejar.DefaultCookieFile())
			cookieJar, _ = cookiejar.New(nil)
		}
	}
	var telemetryInstance telemetry.IdsecTelemetry
	if enableTelemetry && config.IsTelemetryCollectionEnabled() {
		telemetryInstance = telemetry.NewDefaultIdsecSyncTelemetry()
	} else {
		telemetryInstance = telemetry.NewLimitedIdsecSyncTelemetry()
	}

	// Support HTTP/HTTPS proxies via standard env vars (HTTP_PROXY/HTTPS_PROXY/NO_PROXY, etc.).
	// This uses Go's default ProxyFromEnvironment behavior with extra overlay of idsec.
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if caCert := config.TrustedCertificate(); caCert != "" {
		rootCAs.AppendCertsFromPEM([]byte(caCert))
	}
	if extraCACertsPath := config.ExtraTrustedCACertsBundlePath(); extraCACertsPath != "" {
		rootDir := filepath.Dir(extraCACertsPath)
		fileName := filepath.Base(extraCACertsPath)

		root, err := os.OpenRoot(rootDir)
		if err == nil {
			defer func() { _ = root.Close() }()

			file, err := root.Open(fileName)
			if err == nil {
				defer func() { _ = file.Close() }()

				caCertsData, err := io.ReadAll(file)
				if err == nil {
					rootCAs.AppendCertsFromPEM(caCertsData)
				}
			}
		}
	}
	transport := &http.Transport{
		Proxy: config.ConfigureProxy,
		TLSClientConfig: &tls.Config{
			RootCAs:            rootCAs,
			InsecureSkipVerify: !config.IsVerifyingCertificates(), // #nosec G402
			MinVersion:         tls.VersionTLS12,
		},
	}
	httpClient := &http.Client{
		Transport: transport,
	}
	if cookieJar != nil {
		httpClient.Jar = cookieJar
	}

	client := &IdsecClient{
		BaseURL:                   baseURL,
		authHeaderName:            authHeaderName,
		cookieJar:                 cookieJar,
		client:                    httpClient,
		headers:                   make(map[string]string),
		refreshConnectionCallback: refreshCallback,
		owningService:             owningService,
		telemetry:                 telemetryInstance,
		logger:                    GetLogger("IdsecClient", Unknown),
		retryCallback:             nil,
		retryCount:                1,
		transientRetryCount:       defaultTransientRetryCount,
		transientRetryBaseWait:    defaultTransientRetryBaseWait,
		transientRetryMaxWait:     defaultTransientRetryMaxWait,
	}
	client.UpdateToken(token, tokenType)
	client.headers["User-Agent"] = config.UserAgent()
	return client
}

// SetHeader sets a single HTTP header for the IdsecClient.
//
// This method adds or updates a single header in the client's header map.
// The header will be included in all subsequent HTTP requests made by this client.
// If a header with the same key already exists, it will be overwritten.
//
// Parameters:
//   - key: The header name (e.g., "Content-Type", "Accept")
//   - value: The header value (e.g., "application/json", "text/plain")
//
// Example:
//
//	client.SetHeader("Content-Type", "application/json")
//	client.SetHeader("Accept", "application/json")
func (ac *IdsecClient) SetHeader(key string, value string) {
	ac.headers[key] = value
}

// SetHeaders replaces all existing headers with the provided header map.
//
// This method completely replaces the client's header map with the new headers.
// Any previously set headers will be lost. Use UpdateHeaders() if you want to
// preserve existing headers while adding new ones.
//
// Parameters:
//   - headers: Map of header names to values that will replace all existing headers
//
// Example:
//
//	headers := map[string]string{
//	    "Content-Type": "application/json",
//	    "Accept": "application/json",
//	}
//	client.SetHeaders(headers)
func (ac *IdsecClient) SetHeaders(headers map[string]string) {
	ac.headers = headers
}

// UpdateHeaders merges the provided headers into the existing header map.
//
// This method adds new headers or updates existing ones while preserving
// headers that are not specified in the input map. If a header key already
// exists, its value will be overwritten.
//
// Parameters:
//   - headers: Map of header names to values to add or update
//
// Example:
//
//	newHeaders := map[string]string{
//	    "X-Custom-Header": "custom-value",
//	    "Authorization": "Bearer new-token",
//	}
//	client.UpdateHeaders(newHeaders)
func (ac *IdsecClient) UpdateHeaders(headers map[string]string) {
	for key, value := range headers {
		ac.headers[key] = value
	}
}

// GetHeaders returns a copy of the current header map.
//
// This method returns the client's current headers. Note that modifying
// the returned map will not affect the client's headers - use SetHeader()
// or UpdateHeaders() to modify headers.
//
// Returns a map containing all current headers.
//
// Example:
//
//	currentHeaders := client.GetHeaders()
//	fmt.Printf("Content-Type: %s\n", currentHeaders["Content-Type"])
func (ac *IdsecClient) GetHeaders() map[string]string {
	return ac.headers
}

// RemoveHeader removes a single HTTP header from the IdsecClient.
//
// This method deletes the specified header from the client's header map.
// The header will no longer be included in subsequent HTTP requests made by this client.
//
// Parameters:
//   - key: The header name to remove (e.g., "Authorization", "Content-Type")
//
// Example:
//
//	client.RemoveHeader("Authorization")
//	client.RemoveHeader("X-Custom-Header")
func (ac *IdsecClient) RemoveHeader(key string) {
	delete(ac.headers, key)
}

// DisableRedirections disables automatic HTTP redirection handling.
//
// This method configures the underlying HTTP client to not follow redirects.
// When disabled, the client will return the first response received, even if it
// is a redirect (3xx status code). This is useful for scenarios where redirect
// responses need to be handled manually.
//
// Example:
//
//	client.DisableRedirections()
//	// Now, GET requests will not follow redirects automatically.
func (ac *IdsecClient) DisableRedirections() {
	ac.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

// EnableRedirections enables automatic HTTP redirection handling.
//
// This method restores the default behavior of the underlying HTTP client,
// allowing it to automatically follow HTTP redirects (3xx status codes).
// Use this when you want the client to transparently follow redirects.
//
// Example:
//
//	client.EnableRedirections()
//	// Now, GET requests will follow redirects automatically.
func (ac *IdsecClient) EnableRedirections() {
	ac.client.CheckRedirect = nil
}

// SetCookie sets a single cookie in the client's cookie jar.
//
// This method adds a new cookie to the client's cookie jar, which will be
// included in subsequent requests to the appropriate domain. The cookie
// is associated with the client's base URL.
//
// Parameters:
//   - key: The cookie name
//   - value: The cookie value
//
// Example:
//
//	client.SetCookie("session_id", "abc123")
//	client.SetCookie("user_pref", "dark_mode")
func (ac *IdsecClient) SetCookie(key string, value string) {
	parsedURL, err := url.Parse(ac.BaseURL)
	if err != nil {
		ac.logger.Error("Fail to parse url %s: %v", ac.BaseURL, err)
		parsedURL = &url.URL{
			Scheme: "https",
			Host:   ac.BaseURL,
		}
	}
	ac.cookieJar.SetCookies(
		parsedURL,
		[]*http.Cookie{
			{
				Name:  key,
				Value: value,
			},
		},
	)
}

// SetCookies replaces all existing cookies with the provided cookie map.
//
// This method removes all existing cookies from the cookie jar and replaces
// them with the new cookies. Use UpdateCookies() if you want to preserve
// existing cookies while adding new ones.
//
// Parameters:
//   - cookies: Map of cookie names to values that will replace all existing cookies
//
// Example:
//
//	cookies := map[string]string{
//	    "session_id": "abc123",
//	    "csrf_token": "xyz789",
//	}
//	client.SetCookies(cookies)
func (ac *IdsecClient) SetCookies(cookies map[string]string) {
	ac.cookieJar.RemoveAll()
	for key, value := range cookies {
		ac.SetCookie(key, value)
	}
}

// UpdateCookies adds or updates cookies in the existing cookie jar.
//
// This method adds new cookies or updates existing ones while preserving
// cookies that are not specified in the input map.
//
// Parameters:
//   - cookies: Map of cookie names to values to add or update
//
// Example:
//
//	newCookies := map[string]string{
//	    "new_session": "def456",
//	    "updated_pref": "light_mode",
//	}
//	client.UpdateCookies(newCookies)
func (ac *IdsecClient) UpdateCookies(cookies map[string]string) {
	for key, value := range cookies {
		ac.SetCookie(key, value)
	}
}

// GetCookies returns a map of all current cookies.
//
// This method extracts all cookies from the cookie jar and returns them
// as a simple map of names to values. This is useful for inspecting
// current cookie state or for serialization purposes.
//
// Note: This implementation uses the AllCookies() method from persistent-cookiejar
// which provides direct access to all stored cookies.
//
// Returns a map containing all current cookie names and values.
//
// Example:
//
//	cookies := client.GetCookies()
//	sessionID := cookies["session_id"]
func (ac *IdsecClient) GetCookies() map[string]string {
	cookies := make(map[string]string)
	for _, cookie := range ac.cookieJar.AllCookies() {
		cookies[cookie.Name] = cookie.Value
	}
	return cookies
}

// GetCookieJar returns the underlying cookie jar instance.
//
// This method provides direct access to the cookiejar.Jar for advanced
// cookie management operations that are not covered by the convenience
// methods. Use this when you need full control over cookie behavior.
//
// Returns the cookie jar instance used by this client.
//
// Example:
//
//	jar := client.GetCookieJar()
//	// Perform advanced cookie operations
//	cookieData, err := MarshalCookies(jar)
func (ac *IdsecClient) GetCookieJar() *cookiejar.Jar {
	return ac.cookieJar
}

// AddExtraContextField adds a tool-specific context field to telemetry metadata.
//
// This method allows any tool (Terraform, CLI, SDK, etc.) to add arbitrary context
// fields to the telemetry metadata. Tools provide both a full descriptive name and
// a short name for efficient transmission.
//
// Parameters:
//   - name: The full descriptive name for the field (e.g., "terraform_resource", "cli_command")
//   - shortName: The short identifier for the field (e.g., "tfr", "clic")
//   - value: The value to associate with this field
//
// Common usage by tool:
//   - Terraform: ("terraform_resource", "tfr", "idsec_user")
//   - CLI: ("cli_command", "clic", "login")
//   - SDK: Tool-specific fields as needed
//
// This method is typically called before executing operations to provide visibility
// into which tool and context is making the request.
//
// Example:
//
//	client.AddExtraContextField("terraform_resource", "tfr", "idsec_user")
//	client.AddExtraContextField("terraform_operation", "tfo", "Create")
//	client.AddExtraContextField("terraform_version", "tfv", "1.5.0")
//	defer client.ClearExtraContext()
func (ac *IdsecClient) AddExtraContextField(name, shortName, value string) {
	if ac.telemetry != nil {
		collector := ac.telemetry.CollectorByName(collectors.IdsecMetadataMetricsCollectorName)
		if collector != nil {
			if metadataCollector, ok := collector.(*collectors.IdsecMetadataMetricsCollector); ok {
				metadataCollector.AddExtraContextField(name, shortName, value)
			}
		}
	}
}

// ClearExtraContext clears all tool-specific context fields from telemetry metadata.
//
// This method resets all dynamically added tool context fields in the telemetry
// metadata collector. It should typically be called using defer after adding tool
// context to ensure cleanup even if the operation panics or errors.
//
// Example:
//
//	client.AddExtraContextField("tfr", "idsec_policy_db")
//	client.AddExtraContextField("tfo", "create")
//	defer client.ClearExtraContext()
func (ac *IdsecClient) ClearExtraContext() {
	if ac.telemetry != nil {
		collector := ac.telemetry.CollectorByName(collectors.IdsecMetadataMetricsCollectorName)
		if collector != nil {
			if metadataCollector, ok := collector.(*collectors.IdsecMetadataMetricsCollector); ok {
				metadataCollector.ClearExtraContext()
			}
		}
	}
}

// fillMetadataTelemetry populates telemetry metadata for the current operation.
func (ac *IdsecClient) fillMetadataTelemetry(route string, refreshRetryCountLocal int) {
	collector := ac.telemetry.CollectorByName(collectors.IdsecMetadataMetricsCollectorName)
	if collector != nil {
		metadataCollector, ok := collector.(*collectors.IdsecMetadataMetricsCollector)
		if ok {
			metadataCollector.SetRoute(route)
			metadataCollector.SetService(ac.owningService)
			// Get the caller function name three levels up the stack, since the public method is two levels up
			// This also includes the refresh retry count to differentiate between retries
			pc, _, _, ok := runtime.Caller(3 + refreshRetryCount - refreshRetryCountLocal)
			if !ok {
				return
			}
			fullName := runtime.FuncForPC(pc).Name()

			// Parse class name
			start := strings.LastIndex(fullName, "(")
			end := strings.LastIndex(fullName, ")")
			if start != -1 && end != -1 {
				className := strings.TrimPrefix(fullName[start+1:end], "*")
				metadataCollector.SetClass(className)
			}

			// Parse operation nane
			parts := strings.Split(fullName, ".")
			if len(parts) < 1 {
				return
			}
			operationName := parts[len(parts)-1]
			metadataCollector.SetOperation(operationName)
		}
	}
}

// doRequest is the internal method that handles the actual HTTP request execution.
//
// This method constructs and executes HTTP requests with comprehensive functionality
// including URL construction, JSON serialization, header application, query parameter
// handling, TLS configuration, request logging, and automatic token refresh on
// authentication failures.
//
// The method performs several key operations:
// - URL construction with proper path escaping
// - JSON marshaling of request body
// - Header and query parameter application
// - TLS configuration based on certificate verification settings
// - Request timing and logging
// - Automatic retry with token refresh on 401 responses
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - method: HTTP method (GET, POST, PUT, DELETE, etc.)
//   - route: API route/path to append to the base URL
//   - body: Request body to be JSON-serialized (can be nil for methods like GET)
//   - params: Query parameters to include in the request URL (can be nil)
//   - refreshRetryCount: Number of retry attempts remaining for token refresh
//
// Returns the HTTP response or an error if the request fails or retry attempts
// are exhausted.
//
// The method automatically handles:
// - HTTPS URL construction with proper path segment escaping
// - JSON serialization of request bodies
// - Application of all configured headers
// - Query parameter encoding
// - TLS certificate verification based on global settings
// - Request/response timing logging
// - Token refresh retry logic on 401 Unauthorized responses
func (ac *IdsecClient) doRequest(ctx context.Context, method string, route string, body interface{}, params interface{}, refreshRetryCountLocal int, retryCountLocal int, transientRetryLocal int) (*http.Response, error) {
	var err error
	fullURL := ac.BaseURL
	if route != "" {
		segments := strings.Split(route, "/")
		for i, segment := range segments {
			segments[i] = url.PathEscape(segment)
		}
		route = strings.Join(segments, "/")
		if fullURL[len(fullURL)-1] != '/' && route[0] != '/' {
			fullURL += "/"
		}
		fullURL += route
	}
	var bodyReader io.Reader
	if body != nil {
		if contentType, ok := ac.headers["Content-Type"]; ok && contentType == "application/x-www-form-urlencoded" {
			if formValues, ok := body.(map[string]string); ok {
				data := url.Values{}
				for key, value := range formValues {
					data.Set(key, value)
				}
				bodyReader = bytes.NewBufferString(data.Encode())
			} else {
				return nil, fmt.Errorf("body must be of type map[string]string for x-www-form-urlencoded content type")
			}
		} else {
			bodyB, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			bodyReader = bytes.NewBuffer(bodyB)
		}
	}
	telemetryHeader := ""
	if ac.telemetry != nil {
		ac.fillMetadataTelemetry(route, refreshRetryCountLocal)
		encodedTelemetry, err := ac.telemetry.CollectAndEncodeMetrics()
		if err != nil {
			ac.logger.Debug("Failed to collect metrics: %v", err)
		} else {
			telemetryHeader = string(encodedTelemetry)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}
	for key, value := range ac.headers {
		if strings.EqualFold(key, "Content-Type") && bodyReader == nil {
			continue
		}
		req.Header.Set(key, value)
	}
	if telemetryHeader != "" {
		req.Header.Set("X-Cybr-Telemetry", telemetryHeader)
	}
	if params != nil {
		urlParams := url.Values{}
		switch p := params.(type) {
		case map[string]string:
			for key, value := range p {
				urlParams.Add(key, value)
			}
		case map[string][]string:
			for key, values := range p {
				for _, value := range values {
					urlParams.Add(key, value)
				}
			}
		default:
			return nil, fmt.Errorf("unsupported params type: %T", params)
		}
		req.URL.RawQuery = urlParams.Encode()
	}

	ac.logger.Info("Running request '%s %s'", method, fullURL)
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		ac.logger.Info("Request '%s %s' took %dms", method, fullURL, duration.Milliseconds())
	}()
	resp, err := ac.client.Do(req)
	if err != nil {
		// Retry transient connection-close style transport errors (e.g. a bare
		// EOF from reusing a stale keep-alive connection). These indicate the
		// request never reached the application, so a retry is safe.
		if transientRetryLocal > 0 && isRetryableTransportError(err, method) {
			attempt := ac.transientRetryCount - transientRetryLocal
			delay := transientRetryBackoff(ac.transientRetryBaseWait, ac.transientRetryMaxWait, attempt)
			ac.logger.Warning("Transient transport error on '%s %s' (attempt %d/%d): %v - retrying in %s",
				method, fullURL, attempt+1, ac.transientRetryCount, err, delay)
			if sleepErr := sleepWithContext(ctx, delay); sleepErr != nil {
				return nil, err
			}
			return ac.doRequest(ctx, method, route, body, params, refreshRetryCountLocal, retryCountLocal, transientRetryLocal-1)
		}
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized && ac.refreshConnectionCallback != nil && refreshRetryCountLocal > 0 {
		err = ac.refreshConnectionCallback(ac)
		if err != nil {
			return nil, err
		}
		ac.logger.Info("Retrying request '%s %s' after refreshing authentication", method, fullURL)
		return ac.doRequest(ctx, method, route, body, params, refreshRetryCountLocal-1, retryCountLocal, transientRetryLocal)
	}
	// Retry rate-limited responses, honoring the server's Retry-After hint when
	// present and otherwise falling back to exponential backoff.
	if resp.StatusCode == http.StatusTooManyRequests && transientRetryLocal > 0 {
		attempt := ac.transientRetryCount - transientRetryLocal
		delay, ok := parseRetryAfter(resp)
		if !ok {
			delay = transientRetryBackoff(ac.transientRetryBaseWait, ac.transientRetryMaxWait, attempt)
		} else if delay > ac.transientRetryMaxWait {
			// Clamp a server-supplied Retry-After to the configured maximum so a
			// large (or malicious/misconfigured) header value cannot stall the
			// caller far beyond the configured backoff cap.
			delay = ac.transientRetryMaxWait
		}
		// Drain and close the body so the underlying connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		ac.logger.Warning("Rate limited (429) on '%s %s' (attempt %d/%d) - retrying in %s",
			method, fullURL, attempt+1, ac.transientRetryCount, delay)
		if sleepErr := sleepWithContext(ctx, delay); sleepErr != nil {
			return nil, sleepErr
		}
		return ac.doRequest(ctx, method, route, body, params, refreshRetryCountLocal, retryCountLocal, transientRetryLocal-1)
	}
	if resp.StatusCode >= http.StatusInternalServerError && ac.retryCallback != nil && retryCountLocal > 0 && ac.retryCallback(ac, req, resp) {
		ac.logger.Info("Retrying request '%s %s' due to server error %d", method, fullURL, resp.StatusCode)
		return ac.doRequest(ctx, method, route, body, params, refreshRetryCountLocal, retryCountLocal-1, transientRetryLocal)
	}
	return resp, nil
}

// Get performs an HTTP GET request to the specified route.
//
// This method constructs and executes a GET request using the client's base URL,
// headers, and authentication. Query parameters can be provided via the params map.
// The method handles automatic token refresh on 401 responses if a refresh callback
// is configured.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - route: API route/path to append to the base URL
//   - params: Query parameters to include in the request (nil for no parameters)
//
// Returns the HTTP response or an error if the request fails.
//
// Example:
//
//	params := map[string]string{"limit": "10", "offset": "0"}
//	response, err := client.Get(ctx, "/users", params)
//	if err != nil {
//	    // handle error
//	}
//	defer response.Body.Close()
func (ac *IdsecClient) Get(ctx context.Context, route string, params interface{}) (*http.Response, error) {
	return ac.doRequest(ctx, http.MethodGet, route, nil, params, refreshRetryCount, ac.retryCount, ac.transientRetryCount)
}

// Post performs an HTTP POST request to the specified route.
//
// This method constructs and executes a POST request with the provided body
// serialized as JSON. The request includes all configured headers and
// authentication. Automatic token refresh is handled on 401 responses.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - route: API route/path to append to the base URL
//   - body: Request body data to be JSON-serialized
//
// Returns the HTTP response or an error if the request fails.
//
// Example:
//
//	userData := map[string]string{"name": "John", "email": "john@example.com"}
//	response, err := client.Post(ctx, "/users", userData)
//	if err != nil {
//	    // handle error
//	}
//	defer response.Body.Close()
func (ac *IdsecClient) Post(ctx context.Context, route string, body interface{}) (*http.Response, error) {
	return ac.doRequest(ctx, http.MethodPost, route, body, nil, refreshRetryCount, ac.retryCount, ac.transientRetryCount)
}

// PostWithParams performs an HTTP POST request to the specified route with query parameters.
//
// This method is identical to Post but additionally accepts URL query parameters that
// are appended to the request URL. The body is serialized as JSON. This is useful for
// APIs that require both a POST body and query string parameters.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - route: API route/path to append to the base URL
//   - body: Request body data to be JSON-serialized
//   - params: URL query parameters (map[string]string or map[string][]string)
//
// Returns the HTTP response or an error if the request fails.
//
// Example:
//
//	body := map[string]string{"description": "updated"}
//	params := map[string]string{"attributeid": "abc-123"}
//	response, err := client.PostWithParams(ctx, "/SomeApi/Update", body, params)
func (ac *IdsecClient) PostWithParams(ctx context.Context, route string, body interface{}, params interface{}) (*http.Response, error) {
	return ac.doRequest(ctx, http.MethodPost, route, body, params, refreshRetryCount, ac.retryCount, ac.transientRetryCount)
}

// Put performs an HTTP PUT request to the specified route.
//
// This method constructs and executes a PUT request with the provided body
// serialized as JSON. PUT requests are typically used for updating or
// replacing existing resources.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - route: API route/path to append to the base URL
//   - body: Request body data to be JSON-serialized
//
// Returns the HTTP response or an error if the request fails.
//
// Example:
//
//	updatedUser := map[string]string{"name": "John Doe", "email": "john.doe@example.com"}
//	response, err := client.Put(ctx, "/users/123", updatedUser)
func (ac *IdsecClient) Put(ctx context.Context, route string, body interface{}) (*http.Response, error) {
	return ac.doRequest(ctx, http.MethodPut, route, body, nil, refreshRetryCount, ac.retryCount, ac.transientRetryCount)
}

// Delete performs an HTTP DELETE request to the specified route.
//
// This method constructs and executes a DELETE request. An optional body
// can be provided for DELETE requests that require additional data.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - route: API route/path to append to the base URL
//   - body: Optional request body data to be JSON-serialized (can be nil)
//
// Returns the HTTP response or an error if the request fails.
//
// Example:
//
//	response, err := client.Delete(ctx, "/users/123", nil)
//	// Or with body:
//	deleteOptions := map[string]bool{"force": true}
//	response, err := client.Delete(ctx, "/users/123", deleteOptions)
func (ac *IdsecClient) Delete(ctx context.Context, route string, body interface{}, params interface{}) (*http.Response, error) {
	return ac.doRequest(ctx, http.MethodDelete, route, body, params, refreshRetryCount, ac.retryCount, ac.transientRetryCount)
}

// Patch performs an HTTP PATCH request to the specified route.
//
// This method constructs and executes a PATCH request with the provided body
// serialized as JSON. PATCH requests are typically used for partial updates
// of existing resources.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - route: API route/path to append to the base URL
//   - body: Request body data to be JSON-serialized
//
// Returns the HTTP response or an error if the request fails.
//
// Example:
//
//	partialUpdate := map[string]string{"email": "newemail@example.com"}
//	response, err := client.Patch(ctx, "/users/123", partialUpdate)
func (ac *IdsecClient) Patch(ctx context.Context, route string, body interface{}) (*http.Response, error) {
	return ac.doRequest(ctx, http.MethodPatch, route, body, nil, refreshRetryCount, ac.retryCount, ac.transientRetryCount)
}

// Options performs an HTTP OPTIONS request to the specified route.
//
// This method constructs and executes an OPTIONS request, typically used
// to retrieve information about the communication options available for
// the target resource or server.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - route: API route/path to append to the base URL
//
// Returns the HTTP response or an error if the request fails.
//
// Example:
//
//	response, err := client.Options(ctx, "/users")
//	// Check response headers for allowed methods, CORS info, etc.
func (ac *IdsecClient) Options(ctx context.Context, route string) (*http.Response, error) {
	return ac.doRequest(ctx, http.MethodOptions, route, nil, nil, refreshRetryCount, ac.retryCount, ac.transientRetryCount)
}

// UpdateToken updates the authentication token and token type for the client.
//
// This method updates the client's authentication credentials and automatically
// configures the appropriate authorization header. It supports both standard
// token-based authentication and basic authentication. For basic auth, the token
// should be a base64-encoded "username:password" string.
//
// Parameters:
//   - token: The authentication token or base64-encoded credentials
//   - tokenType: The type of token ("Bearer", "Basic", "API-Key", etc.)
//
// The method will automatically set the Authorization header based on the token type:
// - For IdsecAuthorizationTokenTypeRaw: sets the configured auth header to token only
// - For other types: sets the configured auth header with format "<tokenType> <token>"
//
// Example:
//
//	// Bearer token
//	client.UpdateToken("abc123xyz", "Bearer")
//
//	// Basic auth (token should be base64 encoded "user:pass")
//	client.UpdateToken("dXNlcjpwYXNz", "Basic")
//
//	// API key
//	client.UpdateToken("api-key-value", "API-Key")
//
//	// Raw session token (e.g. CyberArk PVWA REST)
//	client.UpdateToken(sessionToken, IdsecAuthorizationTokenTypeRaw)
func (ac *IdsecClient) UpdateToken(token string, tokenType string) {
	ac.token = token
	ac.tokenType = tokenType
	if token == "" {
		return
	}
	if tokenType == IdsecAuthorizationTokenTypeRaw {
		ac.headers[ac.authHeaderName] = token
		return
	}
	ac.headers[ac.authHeaderName] = fmt.Sprintf("%s %s", tokenType, token)
}

// GetToken returns the current authentication token.
//
// This method returns the raw token string that was set via UpdateToken().
// For basic authentication, this will be the base64-encoded credentials.
//
// Returns the current authentication token string.
//
// Example:
//
//	currentToken := client.GetToken()
//	if currentToken == "" {
//	    // No authentication token is set
//	}
func (ac *IdsecClient) GetToken() string {
	return ac.token
}

// GetTokenType returns the current token type.
//
// This method returns the token type that was set via UpdateToken(),
// such as "Bearer", "Basic", "API-Key", etc.
//
// Returns the current token type string.
//
// Example:
//
//	tokenType := client.GetTokenType()
//	fmt.Printf("Using %s authentication\n", tokenType)
func (ac *IdsecClient) GetTokenType() string {
	return ac.tokenType
}

// SetRetry configures the retry behavior for HTTP requests.
//
// This method allows setting a custom retry callback function and the
// maximum number of retry attempts for HTTP requests. The retry callback
// is invoked after each request to determine whether a retry should be
// attempted based on the request and response.
// retry is only attempted if the status code is above 500
// 401 Unauthorized responses are automatically retried if a refresh callback is configured, and do not count against the retry count set by this method.
//
// Note: Consider using IdsecClientRetryStrategy implementations for more
// structured retry behavior instead of directly setting callbacks.
//
// Parameters:
//   - retryCallback: Function that determines whether to retry a request
//     It receives the client, request, and response as parameters
//   - retryCount: Maximum number of retry attempts
//
// Example:
//
//	client.SetRetry(func(c *IdsecClient, req *http.Request, resp *http.Response) bool {
//	    // Retry on 500 Internal Server Error
//	    return resp.StatusCode == http.StatusInternalServerError
//	}, 3)
//
//	// Or use a retry strategy:
//	strategy := &RetryAllErrorsStrategy{MaxRetries: 3}
//	strategy.ConfigureClient(client)
func (ac *IdsecClient) SetRetry(retryCallback func(*IdsecClient, *http.Request, *http.Response) bool, retryCount int) {
	ac.retryCallback = retryCallback
	ac.retryCount = retryCount
}

// SetTransientRetry configures automatic retry of transient failures.
//
// Transient failures are connection-close style transport errors (such as a
// bare "EOF" produced when a stale keep-alive connection is reused) and HTTP
// 429 rate-limit responses. Unlike SetRetry (which is opt-in and only applies
// to 5xx responses), transient retry is enabled by default with sensible
// backoff.
//
// A connection that was closed before the request was processed (a bare "EOF"
// or a closed idle connection) is retried for any method. Ambiguous mid-flight
// transport errors that may occur after the server began processing (e.g. a
// connection reset) are only retried for idempotent methods, so a non-idempotent
// request (such as a POST that creates a resource) is never silently duplicated.
// A server-supplied Retry-After on a 429 is honored but clamped to maxWait.
//
// Parameters:
//   - count: The number of retry attempts for transient failures. A value of 0
//     disables transient retry. Negative values are treated as 0.
//   - baseWait: The base backoff before the first retry. Values <= 0 leave the
//     current base wait unchanged.
//   - maxWait: The maximum backoff between retries (also the upper bound applied
//     to a server-supplied Retry-After). Values <= 0 leave the current maximum
//     wait unchanged.
//
// Example:
//
//	// Retry transient failures up to 5 times, starting at 1s and capping at 30s.
//	client.SetTransientRetry(5, 1*time.Second, 30*time.Second)
//
//	// Disable transient retry entirely.
//	client.SetTransientRetry(0, 0, 0)
func (ac *IdsecClient) SetTransientRetry(count int, baseWait, maxWait time.Duration) {
	if count < 0 {
		count = 0
	}
	ac.transientRetryCount = count
	if baseWait > 0 {
		ac.transientRetryBaseWait = baseWait
	}
	if maxWait > 0 {
		ac.transientRetryMaxWait = maxWait
	}
}

// isIdempotentMethod reports whether an HTTP method is idempotent per RFC 7231
// (repeating the request has the same effect as issuing it once), and is
// therefore safe to retry even when the request may already have reached the
// server.
//
// Parameters:
//   - method: The HTTP method (case-insensitive).
//
// Returns true for GET, HEAD, OPTIONS, TRACE, PUT, and DELETE.
func isIdempotentMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

// isRetryableTransportError reports whether a transport-level error returned by
// http.Client.Do represents a transient, connection-close style failure that is
// safe to retry for the given HTTP method.
//
// It deliberately excludes context cancellation and deadline errors (which
// reflect caller intent and must be honored) and generic timeouts (which are
// ambiguous with respect to whether the server processed the request).
//
// Errors are split into two classes:
//   - Connection-closed-before-processing (a bare "EOF" or a closed idle
//     connection). These occur when a stale keep-alive connection is reused and
//     the server had already closed it, so the request never reached the
//     application. They are safe to retry for ANY method, including POST - this
//     is the failure mode OLY-18600 was reported for.
//   - Ambiguous mid-flight resets ("connection reset", "broken pipe",
//     "http2: server sent goaway"). These can occur after the server began
//     processing the request, so retrying a non-idempotent method (e.g. POST)
//     could duplicate a side effect. They are only retried for idempotent
//     methods.
//
// Parameters:
//   - err: The error returned by the HTTP client.
//   - method: The HTTP method of the request that produced the error.
//
// Returns true if the error is a retryable transient transport error for the
// given method.
func isRetryableTransportError(err error, method string) bool {
	if err == nil {
		return false
	}
	// Never retry when the caller cancelled or the deadline elapsed.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Connection closed without the request being processed - safe for any
	// method (the stale keep-alive reuse case).
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	unprocessedSubstrings := []string{
		"eof",
		"server closed idle connection",
	}
	for _, substr := range unprocessedSubstrings {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	// Ambiguous errors that may occur after the server began processing the
	// request are only safe to retry for idempotent methods.
	if isIdempotentMethod(method) {
		ambiguousSubstrings := []string{
			"connection reset by peer",
			"connection reset",
			"broken pipe",
			"http2: server sent goaway",
		}
		for _, substr := range ambiguousSubstrings {
			if strings.Contains(msg, substr) {
				return true
			}
		}
	}
	return false
}

// parseRetryAfter extracts a delay from an HTTP response's Retry-After header.
//
// The header may be expressed either as an integer number of seconds or as an
// HTTP date. Negative or past values are clamped to zero.
//
// Parameters:
//   - resp: The HTTP response to inspect (may be nil).
//
// Returns the parsed delay and true when a valid Retry-After header is present,
// or a zero duration and false otherwise.
func parseRetryAfter(resp *http.Response) (time.Duration, bool) {
	if resp == nil {
		return 0, false
	}
	value := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			seconds = 0
		}
		return time.Duration(seconds) * time.Second, true
	}
	if t, err := http.ParseTime(value); err == nil {
		delay := time.Until(t)
		if delay < 0 {
			delay = 0
		}
		return delay, true
	}
	return 0, false
}

// transientRetryBackoff computes the backoff before a transient retry attempt.
//
// The delay grows exponentially from base (doubling each attempt) up to the max
// cap, with up to 50% random jitter added to avoid synchronized retries across
// concurrent requests (the "thundering herd" problem).
//
// Parameters:
//   - base: The base delay for the first attempt.
//   - max: The maximum delay cap.
//   - attempt: The zero-based retry attempt index.
//
// Returns the jittered backoff duration.
func transientRetryBackoff(base, max time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = defaultTransientRetryBaseWait
	}
	if max <= 0 {
		max = defaultTransientRetryMaxWait
	}
	delay := base
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay >= max {
			delay = max
			break
		}
	}
	if delay > max {
		delay = max
	}
	return delay + randomJitter(delay)
}

// randomJitter returns a random duration between 0 and half of the provided
// duration, using a cryptographically secure source. On any error it returns 0.
//
// Parameters:
//   - duration: The base duration to derive jitter from.
//
// Returns the jitter duration to add to a backoff delay.
func randomJitter(duration time.Duration) time.Duration {
	maxJitter := int64(duration) / 2
	if maxJitter <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(maxJitter))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// sleepWithContext sleeps for the given duration but returns early if the
// context is cancelled or its deadline elapses.
//
// Parameters:
//   - ctx: The context governing cancellation.
//   - d: The duration to sleep. Non-positive values return immediately.
//
// Returns the context's error if it is done before the duration elapses, or nil
// once the full duration has passed.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
