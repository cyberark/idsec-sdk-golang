package k8s

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestCLISignature_EmitInteropVectors prints JSON vectors for the Python server
// to verify (caller → callee interop). Invoked with:
//
//	go test ./pkg/services/sca/k8s/ -run EmitInteropVectors -v
func TestCLISignature_EmitInteropVectors(t *testing.T) {
	token := "interop-id-token-from-idsec-caller"
	now := time.Date(2024, 1, 15, 12, 0, 7, 0, time.UTC) // tw = 341064001
	prev := now.Add(-5 * time.Second)                    // tw-1

	type vector struct {
		Name      string `json:"name"`
		Token     string `json:"token"`
		Path      string `json:"path"`
		EventPath string `json:"event_path"` // as API GW may present (with /api)
		Unix      int64  `json:"unix"`
		Window    int64  `json:"window"`
		Signature string `json:"signature"`
	}

	paths := []struct {
		name      string
		path      string
		eventPath string
	}{
		{"evaluate_aws", "/access/AWS/eligibility/clusters/evaluate", "/api/access/AWS/eligibility/clusters/evaluate"},
		{"elevate", "/access/elevate/clusters", "/api/access/elevate/clusters"},
	}

	var vectors []vector
	for _, p := range paths {
		for _, ts := range []time.Time{now, prev} {
			label := "tw"
			if ts.Equal(prev) {
				label = "tw-1"
			}
			vectors = append(vectors, vector{
				Name:      fmt.Sprintf("%s_%s", p.name, label),
				Token:     token,
				Path:      p.path,
				EventPath: p.eventPath,
				Unix:      ts.Unix(),
				Window:    cliSignatureTimeWindow(ts),
				Signature: computeCLISignature(token, p.path, ts),
			})
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vectors); err != nil {
		t.Fatal(err)
	}
}

func TestCLISignature_TwAndTwMinusOneDiffer(t *testing.T) {
	token := "tok"
	path := "/access/elevate/clusters"
	now := time.Date(2024, 1, 15, 12, 0, 7, 0, time.UTC)
	prev := now.Add(-5 * time.Second)

	sigTw := computeCLISignature(token, path, now)
	sigPrev := computeCLISignature(token, path, prev)
	if sigTw == sigPrev {
		t.Fatalf("tw and tw-1 must produce different signatures")
	}
	if cliSignatureTimeWindow(now) != cliSignatureTimeWindow(prev)+1 {
		t.Fatalf("expected consecutive windows, got tw=%d tw-1=%d",
			cliSignatureTimeWindow(now), cliSignatureTimeWindow(prev))
	}
}
