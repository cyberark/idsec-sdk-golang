// Package internal provides shared PVWA REST helpers for PAM self-hosted SDK services.
package internal

import (
	"io"
	"net/http"

	idseccommon "github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// ClosePVWAResponse drains and closes a PVWA HTTP response body so the connection can be reused.
func ClosePVWAResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if err := resp.Body.Close(); err != nil {
		idseccommon.GlobalLogger.Warning("Error closing response body")
	}
}
