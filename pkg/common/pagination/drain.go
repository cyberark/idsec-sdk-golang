package pagination

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// DrainPages collects all items from paginated list channels into a single slice.
func DrainPages[T any](pages <-chan *common.IdsecPage[T], errCh <-chan error) ([]*T, error) {
	items := make([]*T, 0)
	for page := range pages {
		items = append(items, page.Items...)
	}
	if err := <-errCh; err != nil {
		return nil, err
	}
	return items, nil
}
