package k8s

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
)

const (
	cliSignatureHeader        = "X-CLI-Signature"
	cliSignatureWindowSeconds = int64(5)
	cliSignatureSeparator     = "|"
)

// cliSignatureTimeWindow returns floor(UTC unix seconds / 5).
func cliSignatureTimeWindow(now time.Time) int64 {
	return now.UTC().Unix() / cliSignatureWindowSeconds
}

// normalizeCLISignaturePath returns the API-relative path with a leading slash.
func normalizeCLISignaturePath(route string) string {
	route = strings.TrimSpace(route)
	if route == "" {
		return "/"
	}
	if !strings.HasPrefix(route, "/") {
		return "/" + route
	}
	return route
}

// computeCLISignature builds Base64(HMAC-SHA256(ID_TOKEN, time_window|"|"|path)).
func computeCLISignature(idToken, requestPath string, now time.Time) string {
	message := strconv.FormatInt(cliSignatureTimeWindow(now), 10) +
		cliSignatureSeparator +
		normalizeCLISignaturePath(requestPath)
	mac := hmac.New(sha256.New, []byte(idToken))
	_, _ = mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func withCLISignature(client *common.IdsecClient, route string, fn func() (*http.Response, error)) (*http.Response, error) {
	if client == nil {
		return nil, fmt.Errorf("ISP client is not available for CLI signature")
	}
	token := strings.TrimSpace(client.GetToken())
	if token == "" {
		return nil, fmt.Errorf("ISP auth token is not available for CLI signature")
	}
	client.SetHeader(cliSignatureHeader, computeCLISignature(token, route, time.Now().UTC()))
	defer client.RemoveHeader(cliSignatureHeader)
	return fn()
}

func ispClientForSignature(c *isp.IdsecISPServiceClient) (*common.IdsecClient, error) {
	if c == nil || c.IdsecClient == nil {
		return nil, fmt.Errorf("ISP client is not available for CLI signature")
	}
	return c.IdsecClient, nil
}

// postWithCLISignature POSTs with X-CLI-Signature on the SCA ISP client.
func (s *IdsecSCAK8sService) postWithCLISignature(route string, body interface{}) (*http.Response, error) {
	ispClient := s.ISPClient()
	client, err := ispClientForSignature(ispClient)
	if err != nil {
		return nil, err
	}
	return withCLISignature(client, route, func() (*http.Response, error) {
		return ispClient.Post(context.Background(), route, body)
	})
}

// getWithCLISignature GETs with X-CLI-Signature on the given ISP client (SCA or DPA).
func (s *IdsecSCAK8sService) getWithCLISignature(ispClient *isp.IdsecISPServiceClient, route string, params interface{}) (*http.Response, error) {
	client, err := ispClientForSignature(ispClient)
	if err != nil {
		return nil, err
	}
	return withCLISignature(client, route, func() (*http.Response, error) {
		return ispClient.Get(context.Background(), route, params)
	})
}
