package pagination

import (
	"context"
	"net/http"
)

// Getter is the minimal client surface HTTPGetFetch needs. It is satisfied by
// the SDK clients returned from ISPClient()/PVWAClient() (which embed *common.IdsecClient).
type Getter interface {
	Get(ctx context.Context, path string, query interface{}) (*http.Response, error)
}
