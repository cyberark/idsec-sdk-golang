package common

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

func TestMarshalCookies(t *testing.T) {
	tests := []struct {
		name          string
		setupJar      func() *cookiejar.Jar
		validateFunc  func(t *testing.T, result []byte)
		expectedError bool
	}{
		{
			name: "success_marshals_single_cookie",
			setupJar: func() *cookiejar.Jar {
				jar, _ := cookiejar.New(nil)
				parsedURL, _ := url.Parse("https://example.com")
				jar.SetCookies(parsedURL, []*http.Cookie{
					{Name: "session", Value: "abc123"},
				})
				return jar
			},
			validateFunc: func(t *testing.T, result []byte) {
				var cookies []cookieJSON
				if err := json.Unmarshal(result, &cookies); err != nil {
					t.Errorf("Failed to unmarshal cookies: %v", err)
					return
				}
				if len(cookies) != 1 {
					t.Errorf("Expected 1 cookie, got %d", len(cookies))
					return
				}
				if cookies[0].Name != "session" {
					t.Errorf("Expected cookie name 'session', got '%s'", cookies[0].Name)
				}
				if cookies[0].Value != "abc123" {
					t.Errorf("Expected cookie value 'abc123', got '%s'", cookies[0].Value)
				}
			},
			expectedError: false,
		},
		{
			name: "success_marshals_multiple_cookies",
			setupJar: func() *cookiejar.Jar {
				jar, _ := cookiejar.New(nil)
				parsedURL, _ := url.Parse("https://example.com")
				jar.SetCookies(parsedURL, []*http.Cookie{
					{Name: "session", Value: "abc123"},
					{Name: "csrf", Value: "xyz789"},
					{Name: "user_pref", Value: "dark_mode"},
				})
				return jar
			},
			validateFunc: func(t *testing.T, result []byte) {
				var cookies []cookieJSON
				if err := json.Unmarshal(result, &cookies); err != nil {
					t.Errorf("Failed to unmarshal cookies: %v", err)
					return
				}
				if len(cookies) != 3 {
					t.Errorf("Expected 3 cookies, got %d", len(cookies))
				}
			},
			expectedError: false,
		},
		{
			name: "success_marshals_empty_cookie_jar",
			setupJar: func() *cookiejar.Jar {
				jar, _ := cookiejar.New(nil)
				return jar
			},
			validateFunc: func(t *testing.T, result []byte) {
				var cookies []cookieJSON
				if err := json.Unmarshal(result, &cookies); err != nil {
					t.Errorf("Failed to unmarshal cookies: %v", err)
					return
				}
				if len(cookies) != 0 {
					t.Errorf("Expected 0 cookies, got %d", len(cookies))
				}
			},
			expectedError: false,
		},
		{
			name: "success_marshals_cookie_with_all_attributes",
			setupJar: func() *cookiejar.Jar {
				jar, _ := cookiejar.New(nil)
				parsedURL, _ := url.Parse("https://example.com")
				expires := time.Now().Add(24 * time.Hour)
				jar.SetCookies(parsedURL, []*http.Cookie{
					{
						Name:     "full_cookie",
						Value:    "test_value",
						Path:     "/api",
						Domain:   "example.com",
						Expires:  expires,
						MaxAge:   86400,
						Secure:   true,
						HttpOnly: true,
						SameSite: http.SameSiteStrictMode,
					},
				})
				return jar
			},
			validateFunc: func(t *testing.T, result []byte) {
				var cookies []cookieJSON
				if err := json.Unmarshal(result, &cookies); err != nil {
					t.Errorf("Failed to unmarshal cookies: %v", err)
					return
				}
				if len(cookies) != 1 {
					t.Errorf("Expected 1 cookie, got %d", len(cookies))
					return
				}
				cookie := cookies[0]
				if cookie.Name != "full_cookie" {
					t.Errorf("Expected cookie name 'full_cookie', got '%s'", cookie.Name)
				}
				if cookie.Secure != true {
					t.Error("Expected Secure to be true")
				}
				if cookie.HTTPOnly != true {
					t.Error("Expected HTTPOnly to be true")
				}
			},
			expectedError: false,
		},
		{
			name: "success_returns_valid_json",
			setupJar: func() *cookiejar.Jar {
				jar, _ := cookiejar.New(nil)
				parsedURL, _ := url.Parse("https://example.com")
				jar.SetCookies(parsedURL, []*http.Cookie{
					{Name: "test", Value: "value"},
				})
				return jar
			},
			validateFunc: func(t *testing.T, result []byte) {
				if !json.Valid(result) {
					t.Error("Expected valid JSON output")
				}
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			jar := tt.setupJar()
			result, err := MarshalCookies(jar)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestUnmarshalCookies(t *testing.T) {
	tests := []struct {
		name          string
		cookiesData   []byte
		validateFunc  func(t *testing.T, jar *cookiejar.Jar)
		expectedError bool
	}{
		{
			name: "success_unmarshals_single_cookie",
			cookiesData: []byte(`[{
				"name": "session",
				"value": "abc123",
				"domain": "example.com",
				"path": "/"
			}]`),
			validateFunc: func(t *testing.T, jar *cookiejar.Jar) {
				cookies := jar.AllCookies()
				if len(cookies) != 1 {
					t.Errorf("Expected 1 cookie, got %d", len(cookies))
					return
				}
				if cookies[0].Name != "session" {
					t.Errorf("Expected cookie name 'session', got '%s'", cookies[0].Name)
				}
				if cookies[0].Value != "abc123" {
					t.Errorf("Expected cookie value 'abc123', got '%s'", cookies[0].Value)
				}
			},
			expectedError: false,
		},
		{
			name: "success_unmarshals_multiple_cookies",
			cookiesData: []byte(`[
				{"name": "session", "value": "abc123", "domain": "example.com", "path": "/"},
				{"name": "csrf", "value": "xyz789", "domain": "example.com", "path": "/"},
				{"name": "user_pref", "value": "dark_mode", "domain": "example.com", "path": "/"}
			]`),
			validateFunc: func(t *testing.T, jar *cookiejar.Jar) {
				cookies := jar.AllCookies()
				if len(cookies) != 3 {
					t.Errorf("Expected 3 cookies, got %d", len(cookies))
				}
			},
			expectedError: false,
		},
		{
			name:        "success_unmarshals_empty_array",
			cookiesData: []byte(`[]`),
			validateFunc: func(t *testing.T, jar *cookiejar.Jar) {
				cookies := jar.AllCookies()
				if len(cookies) != 0 {
					t.Errorf("Expected 0 cookies, got %d", len(cookies))
				}
			},
			expectedError: false,
		},
		{
			name: "success_unmarshals_cookie_with_all_attributes",
			cookiesData: []byte(`[{
				"name": "full_cookie",
				"value": "test_value",
				"path": "/api",
				"domain": "example.com",
				"max_age": 86400,
				"secure": true,
				"http_only": true,
				"same_site": 3
			}]`),
			validateFunc: func(t *testing.T, jar *cookiejar.Jar) {
				cookies := jar.AllCookies()
				if len(cookies) != 1 {
					t.Errorf("Expected 1 cookie, got %d", len(cookies))
					return
				}
				cookie := cookies[0]
				if cookie.Name != "full_cookie" {
					t.Errorf("Expected cookie name 'full_cookie', got '%s'", cookie.Name)
				}
				if cookie.Secure != true {
					t.Error("Expected Secure to be true")
				}
				if cookie.HttpOnly != true {
					t.Error("Expected HttpOnly to be true")
				}
			},
			expectedError: false,
		},
		{
			name:          "error_invalid_json",
			cookiesData:   []byte(`invalid json`),
			expectedError: true,
		},
		{
			name:          "error_malformed_json_array",
			cookiesData:   []byte(`[{incomplete`),
			expectedError: true,
		},
		{
			name: "success_handles_cookies_with_different_domains",
			cookiesData: []byte(`[
				{"name": "cookie1", "value": "val1", "domain": "example.com", "path": "/"},
				{"name": "cookie2", "value": "val2", "domain": "other.com", "path": "/"}
			]`),
			validateFunc: func(t *testing.T, jar *cookiejar.Jar) {
				cookies := jar.AllCookies()
				if len(cookies) != 2 {
					t.Errorf("Expected 2 cookies, got %d", len(cookies))
				}
			},
			expectedError: false,
		},
		{
			name: "success_handles_cookies_with_different_paths",
			cookiesData: []byte(`[
				{"name": "cookie1", "value": "val1", "domain": "example.com", "path": "/"},
				{"name": "cookie2", "value": "val2", "domain": "example.com", "path": "/api"}
			]`),
			validateFunc: func(t *testing.T, jar *cookiejar.Jar) {
				cookies := jar.AllCookies()
				if len(cookies) != 2 {
					t.Errorf("Expected 2 cookies, got %d", len(cookies))
				}
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			jar, _ := cookiejar.New(nil)
			err := UnmarshalCookies(tt.cookiesData, jar)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, jar)
			}
		})
	}
}

func TestNewSimpleIdsecClient(t *testing.T) {
	tests := []struct {
		name         string
		baseURL      string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name:    "success_creates_client_with_http_url",
			baseURL: "example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if !strings.HasPrefix(client.BaseURL, "https://") {
					t.Errorf("Expected URL to have https prefix, got %s", client.BaseURL)
				}
				if client.BaseURL != "https://example.com" {
					t.Errorf("Expected base URL 'https://example.com', got '%s'", client.BaseURL)
				}
			},
		},
		{
			name:    "success_creates_client_with_https_url",
			baseURL: "https://example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.BaseURL != "https://example.com" {
					t.Errorf("Expected base URL 'https://example.com', got '%s'", client.BaseURL)
				}
			},
		},
		{
			name:    "success_initializes_with_empty_token",
			baseURL: "example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.token != "" {
					t.Errorf("Expected empty token, got '%s'", client.token)
				}
			},
		},
		{
			name:    "success_initializes_with_empty_token_type",
			baseURL: "example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.tokenType != "" {
					t.Errorf("Expected empty token type, got '%s'", client.tokenType)
				}
			},
		},
		{
			name:    "success_initializes_authorization_header_name",
			baseURL: "example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.authHeaderName != "Authorization" {
					t.Errorf("Expected auth header name 'Authorization', got '%s'", client.authHeaderName)
				}
			},
		},
		{
			name:    "success_creates_new_cookie_jar",
			baseURL: "example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.cookieJar == nil {
					t.Error("Expected non-nil cookie jar")
				}
			},
		},
		{
			name:    "success_initializes_nil_refresh_callback",
			baseURL: "example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.refreshConnectionCallback != nil {
					t.Error("Expected nil refresh callback")
				}
			},
		},
		{
			name:    "success_initializes_headers_map",
			baseURL: "example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.headers == nil {
					t.Error("Expected non-nil headers map")
				}
			},
		},
		{
			name:    "success_sets_user_agent_header",
			baseURL: "example.com",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if _, exists := client.headers["User-Agent"]; !exists {
					t.Error("Expected User-Agent header to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient(tt.baseURL)

			if client == nil {
				t.Error("Expected non-nil client")
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestNewIdsecClient(t *testing.T) {
	tests := []struct {
		name            string
		baseURL         string
		token           string
		tokenType       string
		authHeaderName  string
		cookieJar       *cookiejar.Jar
		refreshCallback func(*IdsecClient) error
		owningService   string
		enableTelemetry bool
		validateFunc    func(t *testing.T, client *IdsecClient)
	}{
		{
			name:            "success_creates_client_with_all_parameters",
			baseURL:         "https://api.example.com",
			token:           "test-token",
			tokenType:       "Bearer",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: func(c *IdsecClient) error { return nil },
			owningService:   "test-service",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.BaseURL != "https://api.example.com" {
					t.Errorf("Expected base URL 'https://api.example.com', got '%s'", client.BaseURL)
				}
				if client.token != "test-token" {
					t.Errorf("Expected token 'test-token', got '%s'", client.token)
				}
				if client.tokenType != "Bearer" {
					t.Errorf("Expected token type 'Bearer', got '%s'", client.tokenType)
				}
				if client.authHeaderName != "Authorization" {
					t.Errorf("Expected auth header name 'Authorization', got '%s'", client.authHeaderName)
				}
			},
		},
		{
			name:            "success_adds_https_prefix_when_missing",
			baseURL:         "api.example.com",
			token:           "",
			tokenType:       "",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: nil,
			owningService:   "",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if !strings.HasPrefix(client.BaseURL, "https://") {
					t.Errorf("Expected URL to have https prefix, got %s", client.BaseURL)
				}
			},
		},
		{
			name:            "success_creates_cookie_jar_when_nil",
			baseURL:         "example.com",
			token:           "",
			tokenType:       "",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: nil,
			owningService:   "",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.cookieJar == nil {
					t.Error("Expected non-nil cookie jar")
				}
			},
		},
		{
			name:            "success_uses_provided_cookie_jar",
			baseURL:         "example.com",
			token:           "",
			tokenType:       "",
			authHeaderName:  "Authorization",
			cookieJar:       func() *cookiejar.Jar { jar, _ := cookiejar.New(nil); return jar }(),
			refreshCallback: nil,
			owningService:   "",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.cookieJar == nil {
					t.Error("Expected non-nil cookie jar")
				}
			},
		},
		{
			name:            "success_sets_authorization_header_with_token",
			baseURL:         "example.com",
			token:           "abc123",
			tokenType:       "Bearer",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: nil,
			owningService:   "",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				expected := "Bearer abc123"
				if client.headers["Authorization"] != expected {
					t.Errorf("Expected Authorization header '%s', got '%s'", expected, client.headers["Authorization"])
				}
			},
		},
		{
			name:            "success_does_not_set_auth_header_with_empty_token",
			baseURL:         "example.com",
			token:           "",
			tokenType:       "",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: nil,
			owningService:   "",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if _, exists := client.headers["Authorization"]; exists {
					t.Error("Expected no Authorization header with empty token")
				}
			},
		},
		{
			name:            "success_stores_refresh_callback",
			baseURL:         "example.com",
			token:           "",
			tokenType:       "",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: func(c *IdsecClient) error { return errors.New("test") },
			owningService:   "",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.refreshConnectionCallback == nil {
					t.Error("Expected non-nil refresh callback")
				}
			},
		},
		{
			name:            "success_stores_owning_service",
			baseURL:         "example.com",
			token:           "",
			tokenType:       "",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: nil,
			owningService:   "my-service",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.owningService != "my-service" {
					t.Errorf("Expected owning service 'my-service', got '%s'", client.owningService)
				}
			},
		},
		{
			name:            "success_initializes_headers_map",
			baseURL:         "example.com",
			token:           "",
			tokenType:       "",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: nil,
			owningService:   "",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.headers == nil {
					t.Error("Expected non-nil headers map")
				}
			},
		},
		{
			name:            "success_sets_user_agent_header",
			baseURL:         "example.com",
			token:           "",
			tokenType:       "",
			authHeaderName:  "Authorization",
			cookieJar:       nil,
			refreshCallback: nil,
			owningService:   "",
			enableTelemetry: false,
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if _, exists := client.headers["User-Agent"]; !exists {
					t.Error("Expected User-Agent header to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewIdsecClient(
				tt.baseURL,
				tt.token,
				tt.tokenType,
				tt.authHeaderName,
				tt.cookieJar,
				tt.refreshCallback,
				tt.owningService,
				tt.enableTelemetry,
			)

			if client == nil {
				t.Error("Expected non-nil client")
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_SetHeader(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		value        string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name:  "success_sets_new_header",
			key:   "Content-Type",
			value: "application/json",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.headers["Content-Type"] != "application/json" {
					t.Errorf("Expected Content-Type 'application/json', got '%s'", client.headers["Content-Type"])
				}
			},
		},
		{
			name:  "success_overwrites_existing_header",
			key:   "User-Agent",
			value: "custom-agent",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.headers["User-Agent"] != "custom-agent" {
					t.Errorf("Expected User-Agent 'custom-agent', got '%s'", client.headers["User-Agent"])
				}
			},
		},
		{
			name:  "success_sets_custom_header",
			key:   "X-Custom-Header",
			value: "custom-value",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.headers["X-Custom-Header"] != "custom-value" {
					t.Errorf("Expected X-Custom-Header 'custom-value', got '%s'", client.headers["X-Custom-Header"])
				}
			},
		},
		{
			name:  "success_sets_empty_value",
			key:   "Empty-Header",
			value: "",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.headers["Empty-Header"] != "" {
					t.Errorf("Expected Empty-Header '', got '%s'", client.headers["Empty-Header"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			client.SetHeader(tt.key, tt.value)

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_SetHeaders(t *testing.T) {
	tests := []struct {
		name         string
		headers      map[string]string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name: "success_replaces_all_headers",
			headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if _, exists := client.headers["User-Agent"]; exists {
					t.Error("Expected User-Agent header to be removed")
				}
				if client.headers["Content-Type"] != "application/json" {
					t.Error("Expected Content-Type to be set")
				}
				if client.headers["Accept"] != "application/json" {
					t.Error("Expected Accept to be set")
				}
			},
		},
		{
			name:    "success_sets_empty_headers_map",
			headers: map[string]string{},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if len(client.headers) != 0 {
					t.Errorf("Expected 0 headers, got %d", len(client.headers))
				}
			},
		},
		{
			name: "success_sets_single_header",
			headers: map[string]string{
				"X-Custom": "value",
			},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if len(client.headers) != 1 {
					t.Errorf("Expected 1 header, got %d", len(client.headers))
				}
				if client.headers["X-Custom"] != "value" {
					t.Error("Expected X-Custom to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			client.SetHeaders(tt.headers)

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_UpdateHeaders(t *testing.T) {
	tests := []struct {
		name         string
		headers      map[string]string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name: "success_adds_new_headers",
			headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if _, exists := client.headers["User-Agent"]; !exists {
					t.Error("Expected User-Agent header to be preserved")
				}
				if client.headers["Content-Type"] != "application/json" {
					t.Error("Expected Content-Type to be added")
				}
				if client.headers["Accept"] != "application/json" {
					t.Error("Expected Accept to be added")
				}
			},
		},
		{
			name: "success_overwrites_existing_headers",
			headers: map[string]string{
				"User-Agent": "new-agent",
			},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.headers["User-Agent"] != "new-agent" {
					t.Errorf("Expected User-Agent 'new-agent', got '%s'", client.headers["User-Agent"])
				}
			},
		},
		{
			name:    "success_handles_empty_headers_map",
			headers: map[string]string{},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if _, exists := client.headers["User-Agent"]; !exists {
					t.Error("Expected User-Agent header to be preserved")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			client.UpdateHeaders(tt.headers)

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_GetHeaders(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func(*IdsecClient)
		validateFunc func(t *testing.T, headers map[string]string)
	}{
		{
			name: "success_returns_all_headers",
			setupFunc: func(client *IdsecClient) {
				client.SetHeader("Content-Type", "application/json")
				client.SetHeader("Accept", "application/json")
			},
			validateFunc: func(t *testing.T, headers map[string]string) {
				if len(headers) < 2 {
					t.Errorf("Expected at least 2 headers, got %d", len(headers))
				}
				if headers["Content-Type"] != "application/json" {
					t.Error("Expected Content-Type header")
				}
				if headers["Accept"] != "application/json" {
					t.Error("Expected Accept header")
				}
			},
		},
		{
			name:      "success_returns_default_headers",
			setupFunc: func(client *IdsecClient) {},
			validateFunc: func(t *testing.T, headers map[string]string) {
				if _, exists := headers["User-Agent"]; !exists {
					t.Error("Expected User-Agent header")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			headers := client.GetHeaders()

			if tt.validateFunc != nil {
				tt.validateFunc(t, headers)
			}
		})
	}
}

func TestIdsecClient_RemoveHeader(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func(*IdsecClient)
		key          string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name: "success_removes_existing_header",
			setupFunc: func(client *IdsecClient) {
				client.SetHeader("X-Custom", "value")
			},
			key: "X-Custom",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if _, exists := client.headers["X-Custom"]; exists {
					t.Error("Expected X-Custom header to be removed")
				}
			},
		},
		{
			name:      "success_removes_default_header",
			setupFunc: func(client *IdsecClient) {},
			key:       "User-Agent",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if _, exists := client.headers["User-Agent"]; exists {
					t.Error("Expected User-Agent header to be removed")
				}
			},
		},
		{
			name:      "success_handles_nonexistent_header",
			setupFunc: func(client *IdsecClient) {},
			key:       "Nonexistent-Header",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				// Should not panic or error
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			client.RemoveHeader(tt.key)

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_DisableRedirections(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name: "success_disables_redirections",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.client.CheckRedirect == nil {
					t.Error("Expected CheckRedirect to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			client.DisableRedirections()

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_EnableRedirections(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func(*IdsecClient)
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name: "success_enables_redirections",
			setupFunc: func(client *IdsecClient) {
				client.DisableRedirections()
			},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.client.CheckRedirect != nil {
					t.Error("Expected CheckRedirect to be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			client.EnableRedirections()

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_SetCookie(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		value        string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name:  "success_sets_cookie",
			key:   "session",
			value: "abc123",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				cookies := client.GetCookies()
				if cookies["session"] != "abc123" {
					t.Errorf("Expected session cookie 'abc123', got '%s'", cookies["session"])
				}
			},
		},
		{
			name:  "success_sets_multiple_cookies",
			key:   "user_pref",
			value: "dark_mode",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				cookies := client.GetCookies()
				if cookies["user_pref"] != "dark_mode" {
					t.Errorf("Expected user_pref cookie 'dark_mode', got '%s'", cookies["user_pref"])
				}
			},
		},
		{
			name:  "success_overwrites_existing_cookie",
			key:   "session",
			value: "new-value",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				cookies := client.GetCookies()
				if cookies["session"] != "new-value" {
					t.Errorf("Expected session cookie 'new-value', got '%s'", cookies["session"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			client.SetCookie(tt.key, tt.value)

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_SetCookies(t *testing.T) {
	tests := []struct {
		name         string
		cookies      map[string]string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name: "success_replaces_all_cookies",
			cookies: map[string]string{
				"session": "abc123",
				"csrf":    "xyz789",
			},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				cookies := client.GetCookies()
				if len(cookies) != 2 {
					t.Errorf("Expected 2 cookies, got %d", len(cookies))
				}
				if cookies["session"] != "abc123" {
					t.Error("Expected session cookie")
				}
				if cookies["csrf"] != "xyz789" {
					t.Error("Expected csrf cookie")
				}
			},
		},
		{
			name:    "success_sets_empty_cookies_map",
			cookies: map[string]string{},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				cookies := client.GetCookies()
				if len(cookies) != 0 {
					t.Errorf("Expected 0 cookies, got %d", len(cookies))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			client.SetCookies(tt.cookies)

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_UpdateCookies(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func(*IdsecClient)
		cookies      map[string]string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name: "success_adds_new_cookies",
			setupFunc: func(client *IdsecClient) {
				client.SetCookie("existing", "value")
			},
			cookies: map[string]string{
				"new": "cookie",
			},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				cookies := client.GetCookies()
				if cookies["existing"] != "value" {
					t.Error("Expected existing cookie to be preserved")
				}
				if cookies["new"] != "cookie" {
					t.Error("Expected new cookie to be added")
				}
			},
		},
		{
			name: "success_overwrites_existing_cookies",
			setupFunc: func(client *IdsecClient) {
				client.SetCookie("session", "old-value")
			},
			cookies: map[string]string{
				"session": "new-value",
			},
			validateFunc: func(t *testing.T, client *IdsecClient) {
				cookies := client.GetCookies()
				if cookies["session"] != "new-value" {
					t.Errorf("Expected session cookie 'new-value', got '%s'", cookies["session"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			client.UpdateCookies(tt.cookies)

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_GetCookies(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func(*IdsecClient)
		validateFunc func(t *testing.T, cookies map[string]string)
	}{
		{
			name: "success_returns_all_cookies",
			setupFunc: func(client *IdsecClient) {
				client.SetCookie("session", "abc123")
				client.SetCookie("csrf", "xyz789")
			},
			validateFunc: func(t *testing.T, cookies map[string]string) {
				if len(cookies) != 2 {
					t.Errorf("Expected 2 cookies, got %d", len(cookies))
				}
				if cookies["session"] != "abc123" {
					t.Error("Expected session cookie")
				}
				if cookies["csrf"] != "xyz789" {
					t.Error("Expected csrf cookie")
				}
			},
		},
		{
			name:      "success_returns_empty_map_when_no_cookies",
			setupFunc: func(client *IdsecClient) {},
			validateFunc: func(t *testing.T, cookies map[string]string) {
				if len(cookies) != 0 {
					t.Errorf("Expected 0 cookies, got %d", len(cookies))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			cookies := client.GetCookies()

			if tt.validateFunc != nil {
				tt.validateFunc(t, cookies)
			}
		})
	}
}

func TestIdsecClient_GetCookieJar(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, jar *cookiejar.Jar)
	}{
		{
			name: "success_returns_cookie_jar",
			validateFunc: func(t *testing.T, jar *cookiejar.Jar) {
				if jar == nil {
					t.Error("Expected non-nil cookie jar")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			jar := client.GetCookieJar()

			if tt.validateFunc != nil {
				tt.validateFunc(t, jar)
			}
		})
	}
}

func TestIdsecClient_UpdateToken(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		tokenType    string
		validateFunc func(t *testing.T, client *IdsecClient)
	}{
		{
			name:      "success_updates_bearer_token",
			token:     "abc123",
			tokenType: "Bearer",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.token != "abc123" {
					t.Errorf("Expected token 'abc123', got '%s'", client.token)
				}
				if client.tokenType != "Bearer" {
					t.Errorf("Expected token type 'Bearer', got '%s'", client.tokenType)
				}
				expected := "Bearer abc123"
				if client.headers["Authorization"] != expected {
					t.Errorf("Expected Authorization header '%s', got '%s'", expected, client.headers["Authorization"])
				}
			},
		},
		{
			name:      "success_updates_basic_token",
			token:     "base64encoded",
			tokenType: "Basic",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				expected := "Basic base64encoded"
				if client.headers["Authorization"] != expected {
					t.Errorf("Expected Authorization header '%s', got '%s'", expected, client.headers["Authorization"])
				}
			},
		},
		{
			name:      "success_updates_api_key_token",
			token:     "api-key-value",
			tokenType: "API-Key",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				expected := "API-Key api-key-value"
				if client.headers["Authorization"] != expected {
					t.Errorf("Expected Authorization header '%s', got '%s'", expected, client.headers["Authorization"])
				}
			},
		},
		{
			name:      "success_handles_empty_token",
			token:     "",
			tokenType: "",
			validateFunc: func(t *testing.T, client *IdsecClient) {
				if client.token != "" {
					t.Errorf("Expected empty token, got '%s'", client.token)
				}
				if client.tokenType != "" {
					t.Errorf("Expected empty token type, got '%s'", client.tokenType)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			client.UpdateToken(tt.token, tt.tokenType)

			if tt.validateFunc != nil {
				tt.validateFunc(t, client)
			}
		})
	}
}

func TestIdsecClient_GetToken(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(*IdsecClient)
		expectedToken string
	}{
		{
			name: "success_returns_token",
			setupFunc: func(client *IdsecClient) {
				client.UpdateToken("abc123", "Bearer")
			},
			expectedToken: "abc123",
		},
		{
			name:          "success_returns_empty_token",
			setupFunc:     func(client *IdsecClient) {},
			expectedToken: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			token := client.GetToken()

			if token != tt.expectedToken {
				t.Errorf("Expected token '%s', got '%s'", tt.expectedToken, token)
			}
		})
	}
}

func TestIdsecClient_GetTokenType(t *testing.T) {
	tests := []struct {
		name              string
		setupFunc         func(*IdsecClient)
		expectedTokenType string
	}{
		{
			name: "success_returns_bearer_token_type",
			setupFunc: func(client *IdsecClient) {
				client.UpdateToken("abc123", "Bearer")
			},
			expectedTokenType: "Bearer",
		},
		{
			name: "success_returns_basic_token_type",
			setupFunc: func(client *IdsecClient) {
				client.UpdateToken("abc123", "Basic")
			},
			expectedTokenType: "Basic",
		},
		{
			name:              "success_returns_empty_token_type",
			setupFunc:         func(client *IdsecClient) {},
			expectedTokenType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("example.com")
			if tt.setupFunc != nil {
				tt.setupFunc(client)
			}

			tokenType := client.GetTokenType()

			if tokenType != tt.expectedTokenType {
				t.Errorf("Expected token type '%s', got '%s'", tt.expectedTokenType, tokenType)
			}
		})
	}
}

func TestIdsecClient_HTTPMethods(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		setupServer    func() *httptest.Server
		route          string
		body           interface{}
		params         interface{}
		validateFunc   func(t *testing.T, resp *http.Response, err error)
		expectedStatus int
	}{
		{
			name:   "success_get_request",
			method: "GET",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "GET" {
						t.Errorf("Expected GET method, got %s", r.Method)
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"result":"success"}`))
				}))
			},
			route:          "/test",
			params:         nil,
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Expected status 200, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_post_request_with_json_body",
			method: "POST",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "POST" {
						t.Errorf("Expected POST method, got %s", r.Method)
					}
					body, _ := io.ReadAll(r.Body)
					var data map[string]string
					_ = json.Unmarshal(body, &data)
					if data["key"] != "value" {
						t.Error("Expected body to contain key=value")
					}
					w.WriteHeader(http.StatusCreated)
				}))
			},
			route: "/test",
			body: map[string]string{
				"key": "value",
			},
			expectedStatus: http.StatusCreated,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusCreated {
					t.Errorf("Expected status 201, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_put_request",
			method: "PUT",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "PUT" {
						t.Errorf("Expected PUT method, got %s", r.Method)
					}
					w.WriteHeader(http.StatusOK)
				}))
			},
			route: "/test",
			body: map[string]string{
				"update": "data",
			},
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Expected status 200, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_delete_request",
			method: "DELETE",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "DELETE" {
						t.Errorf("Expected DELETE method, got %s", r.Method)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
			},
			route:          "/test",
			body:           nil,
			expectedStatus: http.StatusNoContent,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusNoContent {
					t.Errorf("Expected status 204, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_patch_request",
			method: "PATCH",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "PATCH" {
						t.Errorf("Expected PATCH method, got %s", r.Method)
					}
					w.WriteHeader(http.StatusOK)
				}))
			},
			route: "/test",
			body: map[string]string{
				"partial": "update",
			},
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Expected status 200, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_options_request",
			method: "OPTIONS",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "OPTIONS" {
						t.Errorf("Expected OPTIONS method, got %s", r.Method)
					}
					w.Header().Set("Allow", "GET, POST, PUT, DELETE")
					w.WriteHeader(http.StatusOK)
				}))
			},
			route:          "/test",
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Expected status 200, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_get_request_with_query_parameters",
			method: "GET",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Query().Get("param1") != "value1" {
						t.Error("Expected param1=value1 in query")
					}
					if r.URL.Query().Get("param2") != "value2" {
						t.Error("Expected param2=value2 in query")
					}
					w.WriteHeader(http.StatusOK)
				}))
			},
			route: "/test",
			params: map[string]string{
				"param1": "value1",
				"param2": "value2",
			},
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
			},
		},
		{
			name:   "success_get_request_with_multi_value_parameters",
			method: "GET",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ids := r.URL.Query()["id"]
					if len(ids) != 3 {
						t.Errorf("Expected 3 id parameters, got %d", len(ids))
					}
					if ids[0] != "1" || ids[1] != "2" || ids[2] != "3" {
						t.Error("Expected id parameters to be 1, 2, 3")
					}
					tags := r.URL.Query()["tag"]
					if len(tags) != 2 {
						t.Errorf("Expected 2 tag parameters, got %d", len(tags))
					}
					if tags[0] != "active" || tags[1] != "verified" {
						t.Error("Expected tag parameters to be active, verified")
					}
					w.WriteHeader(http.StatusOK)
				}))
			},
			route: "/test",
			params: map[string][]string{
				"id":  {"1", "2", "3"},
				"tag": {"active", "verified"},
			},
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Expected status 200, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_get_request_with_single_multi_value_parameter",
			method: "GET",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					filters := r.URL.Query()["filter"]
					if len(filters) != 4 {
						t.Errorf("Expected 4 filter parameters, got %d", len(filters))
					}
					expectedFilters := []string{"name:eq:john", "age:gt:25", "status:in:active", "role:ne:admin"}
					for i, expected := range expectedFilters {
						if i < len(filters) && filters[i] != expected {
							t.Errorf("Expected filter[%d] to be '%s', got '%s'", i, expected, filters[i])
						}
					}
					w.WriteHeader(http.StatusOK)
				}))
			},
			route: "/test",
			params: map[string][]string{
				"filter": {"name:eq:john", "age:gt:25", "status:in:active", "role:ne:admin"},
			},
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
			},
		},
		{
			name:   "success_get_request_with_empty_multi_value_parameters",
			method: "GET",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if len(r.URL.Query()) != 0 {
						t.Errorf("Expected no query parameters, got %d", len(r.URL.Query()))
					}
					w.WriteHeader(http.StatusOK)
				}))
			},
			route:          "/test",
			params:         map[string][]string{},
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
			},
		},
		{
			name:   "success_delete_request_with_single_value_parameters",
			method: "DELETE",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "DELETE" {
						t.Errorf("Expected DELETE method, got %s", r.Method)
					}
					if r.URL.Query().Get("force") != "true" {
						t.Error("Expected force=true in query")
					}
					if r.URL.Query().Get("reason") != "cleanup" {
						t.Error("Expected reason=cleanup in query")
					}
					w.WriteHeader(http.StatusNoContent)
				}))
			},
			route: "/test",
			params: map[string]string{
				"force":  "true",
				"reason": "cleanup",
			},
			expectedStatus: http.StatusNoContent,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusNoContent {
					t.Errorf("Expected status 204, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_delete_request_with_multi_value_parameters",
			method: "DELETE",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "DELETE" {
						t.Errorf("Expected DELETE method, got %s", r.Method)
					}
					ids := r.URL.Query()["id"]
					if len(ids) != 3 {
						t.Errorf("Expected 3 id parameters, got %d", len(ids))
					}
					if ids[0] != "100" || ids[1] != "200" || ids[2] != "300" {
						t.Error("Expected id parameters to be 100, 200, 300")
					}
					w.WriteHeader(http.StatusNoContent)
				}))
			},
			route: "/test",
			params: map[string][]string{
				"id": {"100", "200", "300"},
			},
			expectedStatus: http.StatusNoContent,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusNoContent {
					t.Errorf("Expected status 204, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_delete_request_with_body_and_multi_value_parameters",
			method: "DELETE",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "DELETE" {
						t.Errorf("Expected DELETE method, got %s", r.Method)
					}
					body, _ := io.ReadAll(r.Body)
					var data map[string]interface{}
					_ = json.Unmarshal(body, &data)
					if data["cascade"] != true {
						t.Error("Expected body to contain cascade=true")
					}
					ids := r.URL.Query()["id"]
					if len(ids) != 2 {
						t.Errorf("Expected 2 id parameters, got %d", len(ids))
					}
					w.WriteHeader(http.StatusNoContent)
				}))
			},
			route: "/test",
			body: map[string]interface{}{
				"cascade": true,
			},
			params: map[string][]string{
				"id": {"1", "2"},
			},
			expectedStatus: http.StatusNoContent,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if resp.StatusCode != http.StatusNoContent {
					t.Errorf("Expected status 204, got %d", resp.StatusCode)
				}
			},
		},
		{
			name:   "success_delete_request_with_mixed_parameter_values",
			method: "DELETE",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ids := r.URL.Query()["id"]
					if len(ids) != 3 {
						t.Errorf("Expected 3 id parameters, got %d", len(ids))
					}
					categories := r.URL.Query()["category"]
					if len(categories) != 2 {
						t.Errorf("Expected 2 category parameters, got %d", len(categories))
					}
					if r.URL.Query().Get("force") != "true" {
						t.Error("Expected force parameter")
					}
					w.WriteHeader(http.StatusNoContent)
				}))
			},
			route: "/test",
			params: map[string][]string{
				"id":       {"10", "20", "30"},
				"category": {"archive", "backup"},
				"force":    {"true"},
			},
			expectedStatus: http.StatusNoContent,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
			},
		},
		{
			name:   "success_get_request_with_special_characters_in_multi_values",
			method: "GET",
			setupServer: func() *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					queries := r.URL.Query()["query"]
					if len(queries) != 3 {
						t.Errorf("Expected 3 query parameters, got %d", len(queries))
					}
					expectedQueries := []string{"name:John Doe", "email:test@example.com", "role:admin & user"}
					for i, expected := range expectedQueries {
						if i < len(queries) && queries[i] != expected {
							t.Errorf("Expected query[%d] to be '%s', got '%s'", i, expected, queries[i])
						}
					}
					w.WriteHeader(http.StatusOK)
				}))
			},
			route: "/test",
			params: map[string][]string{
				"query": {"name:John Doe", "email:test@example.com", "role:admin & user"},
			},
			expectedStatus: http.StatusOK,
			validateFunc: func(t *testing.T, resp *http.Response, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			config.DisableCertificateVerification()
			client := NewSimpleIdsecClient(server.URL)
			ctx := context.Background()

			var resp *http.Response
			var err error

			switch tt.method {
			case "GET":
				resp, err = client.Get(ctx, tt.route, tt.params)
			case "POST":
				resp, err = client.Post(ctx, tt.route, tt.body)
			case "PUT":
				resp, err = client.Put(ctx, tt.route, tt.body)
			case "DELETE":
				resp, err = client.Delete(ctx, tt.route, tt.body, tt.params)
			case "PATCH":
				resp, err = client.Patch(ctx, tt.route, tt.body)
			case "OPTIONS":
				resp, err = client.Options(ctx, tt.route)
			}

			if resp != nil {
				defer resp.Body.Close()
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, resp, err)
			}
		})
	}
}

func TestIdsecClient_GetWithInvalidParamsType(t *testing.T) {
	tests := []struct {
		name          string
		params        interface{}
		expectedError bool
		errorContains string
	}{
		{
			name:          "error_unsupported_params_type_int",
			params:        123,
			expectedError: true,
			errorContains: "unsupported params type",
		},
		{
			name:          "error_unsupported_params_type_slice",
			params:        []string{"value1", "value2"},
			expectedError: true,
			errorContains: "unsupported params type",
		},
		{
			name:          "error_unsupported_params_type_struct",
			params:        struct{ Key string }{Key: "value"},
			expectedError: true,
			errorContains: "unsupported params type",
		},
		{
			name:          "success_nil_params",
			params:        nil,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			config.DisableCertificateVerification()
			client := NewSimpleIdsecClient(server.URL)
			ctx := context.Background()

			resp, err := client.Get(ctx, "/test", tt.params)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if resp != nil {
				defer resp.Body.Close()
			}
		})
	}
}

func TestIdsecClient_DeleteWithInvalidParamsType(t *testing.T) {
	tests := []struct {
		name          string
		params        interface{}
		expectedError bool
		errorContains string
	}{
		{
			name:          "error_unsupported_params_type_float",
			params:        3.14,
			expectedError: true,
			errorContains: "unsupported params type",
		},
		{
			name:          "error_unsupported_params_type_bool",
			params:        true,
			expectedError: true,
			errorContains: "unsupported params type",
		},
		{
			name: "error_unsupported_params_type_map_int_string",
			params: map[int]string{
				1: "value",
			},
			expectedError: true,
			errorContains: "unsupported params type",
		},
		{
			name:          "success_nil_params",
			params:        nil,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			config.DisableCertificateVerification()
			client := NewSimpleIdsecClient(server.URL)
			ctx := context.Background()

			resp, err := client.Delete(ctx, "/test", nil, tt.params)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if resp != nil {
				defer resp.Body.Close()
			}
		})
	}
}

// Mock implementations for testing

type mockTelemetry struct {
	encodedData []byte
	err         error
	collectors  map[string]collectors.IdsecMetricsCollector
}

func (m *mockTelemetry) CollectAndEncodeMetrics() ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.encodedData, nil
}

func (m *mockTelemetry) CollectorByName(name string) collectors.IdsecMetricsCollector {
	if m.collectors != nil {
		return m.collectors[name]
	}
	return nil
}

type mockMetricsCollector struct {
	name      string
	shortName string
	isDynamic bool
	metrics   *collectors.IdsecMetrics
	err       error
}

func (m *mockMetricsCollector) CollectorName() string {
	return m.name
}

func (m *mockMetricsCollector) CollectorShortName() string {
	return m.shortName
}

func (m *mockMetricsCollector) IsDynamicMetrics() bool {
	return m.isDynamic
}

func (m *mockMetricsCollector) CollectMetrics() (*collectors.IdsecMetrics, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.metrics, nil
}

type mockMetricsEncoder struct {
	encodedData []byte
	err         error
}

func (m *mockMetricsEncoder) EncodeMetrics(metrics []*collectors.IdsecMetrics) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.encodedData, nil
}
