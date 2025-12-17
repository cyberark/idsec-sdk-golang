package sca

import (
	"context"
	"testing"

	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// TestScaDiscovery_NilRequest tests nil request validation.
func TestScaDiscovery_NilRequest(t *testing.T) {
	service := &IdsecSCAService{}
	resp, err := service.Discovery(nil)
	if err == nil {
		t.Fatalf("expected error for nil request, got nil (resp=%v)", resp)
	}
}

// TestScaDiscovery_EmptyCSP tests empty CSP validation.
func TestScaDiscovery_EmptyCSP(t *testing.T) {
	service := &IdsecSCAService{}
	req := &scamodels.IdsecSCADiscoveryRequest{}
	resp, err := service.Discovery(req)
	if err == nil {
		t.Fatalf("expected error for empty CSP, got nil (resp=%v)", resp)
	}
}

// TestScaDiscovery_UnsupportedCSP tests unsupported CSP validation.
func TestScaDiscovery_UnsupportedCSP(t *testing.T) {
	service := &IdsecSCAService{}
	req := &scamodels.IdsecSCADiscoveryRequest{
		CSP:            "ibm",
		OrganizationID: "org",
		AccountInfo:    scamodels.IdsecSCADiscoveryAccountInfo{ID: "acc"},
	}
	resp, err := service.Discovery(req)
	if err == nil {
		t.Fatalf("expected error for unsupported CSP, got nil (resp=%v)", resp)
	}
}

// TestScaDiscovery_MissingOrgID tests missing organization ID validation.
func TestScaDiscovery_MissingOrgID(t *testing.T) {
	service := &IdsecSCAService{}
	req := &scamodels.IdsecSCADiscoveryRequest{CSP: "aws"}
	resp, err := service.Discovery(req)
	if err == nil {
		t.Fatalf("expected error for missing org ID, got nil (resp=%v)", resp)
	}
}

// TestScaDiscovery_MissingAccountID tests missing account ID validation.
func TestScaDiscovery_MissingAccountID(t *testing.T) {
	service := &IdsecSCAService{}
	req := &scamodels.IdsecSCADiscoveryRequest{
		CSP:            "aws",
		OrganizationID: "org",
	}
	resp, err := service.Discovery(req)
	if err == nil {
		t.Fatalf("expected error for missing account ID, got nil (resp=%v)", resp)
	}
}

// TestScaDiscovery_UninitializedService tests uninitialized SCA service error.
func TestScaDiscovery_UninitializedService(t *testing.T) {
	service := &IdsecSCAService{}
	req := &scamodels.IdsecSCADiscoveryRequest{
		CSP:            "aws",
		OrganizationID: "org",
		AccountInfo:    scamodels.IdsecSCADiscoveryAccountInfo{ID: "acc"},
	}
	resp, err := service.Discovery(req)
	if err == nil {
		t.Fatalf("expected error for uninitialized service, got nil (resp=%v)", resp)
	}
}

func assertErr(t *testing.T, name string, gotErr error, expectErr bool, resp any) {
	t.Helper()
	switch {
	case expectErr && gotErr == nil:
		t.Fatalf("%s: expected error, got nil (resp=%v)", name, resp)
	case !expectErr && gotErr != nil:
		t.Fatalf("%s: unexpected error: %v", name, gotErr)
	}
}

func assertResp(t *testing.T, name string, resp *scamodels.IdsecSCADiscoveryResponse) {
	t.Helper()
	if resp == nil || resp.JobID == "" {
		t.Fatalf("%s: expected job response with id", name)
	}
}

func TestDiscovery_validation_only(t *testing.T) {
	service := &IdsecSCAService{}
	tests := []struct {
		name      string
		req       *scamodels.IdsecSCADiscoveryRequest
		expectErr bool
	}{
		{name: "error_nil_request", req: nil, expectErr: true},
	}

	for _, tt := range tests {
		resp, err := service.Discovery(tt.req)
		assertErr(t, tt.name, err, tt.expectErr, resp)
		if !tt.expectErr {
			assertResp(t, tt.name, resp)
		}
	}
}

func TestJobStatus_validation_only(t *testing.T) {
	service := &IdsecSCAService{}
	if _, err := service.jobStatus(""); err == nil {
		t.Fatalf("expected error for empty jobID")
	}
}

func TestCheckIfJobFinished_validation_only(t *testing.T) {
	service := &IdsecSCAService{}
	if finished, _, err := service.checkIfJobFinished(context.Background(), ""); err == nil || finished {
		t.Fatalf("expected error for empty jobID in CheckIfJobFinished")
	}
}
