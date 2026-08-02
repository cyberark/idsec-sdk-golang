package pagination

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// ListPaginatedConfig configures generic list pagination against a REST endpoint.
type ListPaginatedConfig[T any] struct {
	ResourceName string
	// Decode turns a page's raw result map into the typed slice. It owns the full
	// extract + normalize + decode + enrich responsibility for the page.
	Decode func(resultMap map[string]interface{}) ([]*T, error)
	// NextQuery, when set, computes the query for the next page from the decoded result map
	// and the current query. Returning ok=false stops pagination. When nil, the default
	// OData-style behavior (NextLinkFromResultMap + QueryFromNextLink) is used.
	NextQuery func(resultMap map[string]interface{}, current map[string]string) (map[string]string, bool)
}

// ListPaginated fetches all pages from an OData-style list endpoint.
//
// The caller supplies a Fetch function that performs a single page request and reports the
// query it used. The engine owns pagination: it passes nil on the first call (so the fetcher
// supplies its own starting query), then advances the query per page via the NextQuery hook
// (or the default OData next_link behavior) and feeds it back into fetch. This keeps request
// concerns (client, path, headers, initial query) entirely inside the fetcher.
//
// It returns a channel of pages and a buffered error channel (capacity 1). The error channel
// receives at most one error after the page channel is closed. The provided ctx is used for
// every request and to unblock the page channel send if the caller stops consuming.
func ListPaginated[T any](
	ctx context.Context,
	fetch Fetch,
	cfg ListPaginatedConfig[T],
) (<-chan *common.IdsecPage[T], <-chan error) {
	pageChannel := make(chan *common.IdsecPage[T])
	errorChannel := make(chan error, 1)
	var query map[string]string

	go func() {
		defer close(errorChannel)
		defer close(pageChannel)

		sendError := func(err error) {
			errorChannel <- err
		}

		for {
			response, usedQuery, err := fetch(ctx, query)
			if err != nil {
				sendError(fmt.Errorf("failed to list %s: %w", cfg.ResourceName, err))
				return
			}
			if response.StatusCode != http.StatusOK {
				listErr := fmt.Errorf(
					"failed to list %s - [%d] - [%s]",
					cfg.ResourceName,
					response.StatusCode,
					common.SerializeResponseToJSON(response.Body),
				)
				CloseResponse(response)
				sendError(listErr)
				return
			}

			result, err := common.DeserializeJSONSnake(response.Body)
			CloseResponse(response)
			if err != nil {
				sendError(fmt.Errorf("failed to decode list %s response: %w", cfg.ResourceName, err))
				return
			}

			resultMap, ok := result.(map[string]interface{})
			if !ok {
				sendError(fmt.Errorf("failed to list %s: unexpected result type %T", cfg.ResourceName, result))
				return
			}

			items, err := cfg.Decode(resultMap)
			if err != nil {
				sendError(err)
				return
			}

			select {
			case pageChannel <- &common.IdsecPage[T]{Items: items}:
			case <-ctx.Done():
				sendError(ctx.Err())
				return
			}

			if cfg.NextQuery != nil {
				nextQuery, ok := cfg.NextQuery(resultMap, usedQuery)
				if !ok {
					break
				}
				query = nextQuery
				continue
			}

			if nextLink, ok := NextLinkFromResultMap(resultMap); ok {
				nextQuery, err := QueryFromNextLink(nextLink)
				if err != nil {
					sendError(err)
					return
				}
				query = nextQuery
			} else {
				break
			}
		}
	}()

	return pageChannel, errorChannel
}

// ListAllPaginated walks every page of a list endpoint and returns the collected results as a
// single-page channel plus a terminal error.
//
// It adapts the streaming two-channel ListPaginated contract to the (<-chan *IdsecPage[T], error)
// shape that CLI-invoked list actions require: the CLI framework recognizes a returned error for
// failure handling and drains any returned channel for output, but it cannot handle a separate
// <-chan error. ListAllPaginated drains the error channel before returning, so a pagination
// failure surfaces synchronously as the returned error instead of being swallowed.
//
// The trade-off is that all pages are collected before returning (no lazy per-page streaming).
// Use ListPaginated directly when you need to stream pages lazily and can consume the separate
// error channel yourself.
func ListAllPaginated[T any](
	ctx context.Context,
	fetch Fetch,
	cfg ListPaginatedConfig[T],
) (<-chan *common.IdsecPage[T], error) {
	items, err := DrainPages(ListPaginated(ctx, fetch, cfg))
	if err != nil {
		return nil, err
	}
	page := make(chan *common.IdsecPage[T], 1)
	page <- &common.IdsecPage[T]{Items: items}
	close(page)
	return page, nil
}
