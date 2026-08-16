package models

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// TestPolicyConnectionMethod_camelSerialization verifies that the policy-level connection method
// is serialized as the camelCase "connectionMethod" key expected by the policy API, and is omitted
// when empty.
func TestPolicyConnectionMethod_camelSerialization(t *testing.T) {
	t.Parallel()

	withMethod := IdsecPolicyK8sPolicy{ConnectionMethod: "direct"}
	data, err := common.SerializeJSONCamel(withMethod)
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}
	if data["connectionMethod"] != "direct" {
		t.Fatalf("connectionMethod: got %v want %q", data["connectionMethod"], "direct")
	}

	empty := IdsecPolicyK8sPolicy{}
	data, err = common.SerializeJSONCamel(empty)
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}
	if _, ok := data["connectionMethod"]; ok {
		t.Fatalf("did not expect connectionMethod key when unset, got: %v", data["connectionMethod"])
	}
}
