package pagination

import (
	"io"
	"net/http"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// CloseResponse drains and closes an HTTP response body so the connection can be reused.
func CloseResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if err := resp.Body.Close(); err != nil {
		common.GlobalLogger.Warning("Error closing response body")
	}
}
