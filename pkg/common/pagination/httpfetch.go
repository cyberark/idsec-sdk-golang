package pagination

import (
	"context"
	"net/http"
)

// HTTPGetFetch builds a Fetch that issues a GET request against path via client.
//
// It encapsulates the common boilerplate shared by GET-based paginated
// endpoints: seeding the first request with initialQuery when the engine
// passes a nil query, performing the GET, and echoing back the query that was
// actually used so the engine can compute the next page from it.
func HTTPGetFetch(client Getter, path string, initialQuery map[string]string) Fetch {
	return func(ctx context.Context, query map[string]string) (*http.Response, map[string]string, error) {
		if query == nil {
			query = initialQuery
		}
		resp, err := client.Get(ctx, path, query)
		return resp, query, err
	}
}
