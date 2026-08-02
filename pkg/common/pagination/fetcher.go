// Package pagination provides generic, transport-agnostic helpers for walking
// paginated list endpoints and draining their results into an IdsecPage stream.
package pagination

import (
	"context"
	"net/http"
)

// Fetch performs a single page request and returns the raw HTTP response together
// with the query parameters it actually used for that request.
//
// The engine passes nil on the first call, so the fetcher supplies its own starting
// query (filters, page size, etc.); on subsequent calls it receives the engine-computed
// next-page query. Echoing back the query used lets the engine seed its next-page
// computation from the fetcher itself, so callers need not pass an initial query
// separately. The caller owns how each request is made: which client, path, and headers.
type Fetch func(ctx context.Context, query map[string]string) (*http.Response, map[string]string, error)
