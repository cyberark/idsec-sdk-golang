package azure

import (
	"encoding/json"
	"net/http"
)

// captureFirstServiceVersion returns a callback that captures the version of
// the first service in the request body's "services" array.
// Safe to use inside OnRequest (no testify calls in the HTTP handler goroutine).
func captureFirstServiceVersion(version *string) func(*http.Request) {
	return func(r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if services, ok := payload["services"].([]interface{}); ok && len(services) > 0 {
			if svc, ok := services[0].(map[string]interface{}); ok {
				*version, _ = svc["version"].(string)
			}
		}
	}
}
