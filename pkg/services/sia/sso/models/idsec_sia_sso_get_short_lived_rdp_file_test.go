package models

import (
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// validGetShortLivedRDPFile returns a minimal, valid IdsecSIASSOGetShortLivedRDPFile.
func validGetShortLivedRDPFile() *IdsecSIASSOGetShortLivedRDPFile {
	return &IdsecSIASSOGetShortLivedRDPFile{
		Folder:        "/tmp",
		TargetAddress: "mymachine.mydomain.com",
		TargetUser:    "myuser",
	}
}

// Asserting the rule, not just that an error occurred, keeps a case from passing because a
// different rule rejected the value.
func requireVaultedAccountIDRule(t *testing.T, input *IdsecSIASSOGetShortLivedRDPFile, rule string) {
	t.Helper()
	err := validation.ValidateStruct(input)
	require.Error(t, err)
	var fieldErrors validator.ValidationErrors
	require.ErrorAs(t, err, &fieldErrors)
	require.Len(t, fieldErrors, 1)
	require.Equal(t, "vaulted_account_id", validation.FieldPath(fieldErrors[0]))
	require.Equal(t, rule, fieldErrors[0].Tag())
}

// TestIdsecSIASSOGetShortLivedRDPFile_VaultedAccountID ensures the vaulted account ID stays
// optional, but when given is restricted the same way the RDP proxy restricts it when parsing
// the connection string: it requires a target user and must be of the <safe id>_<account id>
// format.
func TestIdsecSIASSOGetShortLivedRDPFile_VaultedAccountID(t *testing.T) {
	t.Run("without_vaulted_account_id_passes", func(t *testing.T) {
		require.NoError(t, validation.ValidateStruct(validGetShortLivedRDPFile()))
	})

	t.Run("without_vaulted_account_id_and_without_target_user_passes", func(t *testing.T) {
		input := validGetShortLivedRDPFile()
		input.TargetUser = ""
		require.NoError(t, validation.ValidateStruct(input))
	})

	t.Run("with_vaulted_account_id_passes", func(t *testing.T) {
		input := validGetShortLivedRDPFile()
		input.VaultedAccountID = "10_10"
		require.NoError(t, validation.ValidateStruct(input))
	})

	// The validation matches the proxy regex rather than requiring positive ids,
	// so the SDK never rejects an ID the proxy would have accepted.
	t.Run("zeroed_vaulted_account_id_passes", func(t *testing.T) {
		input := validGetShortLivedRDPFile()
		input.VaultedAccountID = "0_0"
		require.NoError(t, validation.ValidateStruct(input))
	})

	t.Run("vaulted_account_id_without_target_user_fails", func(t *testing.T) {
		input := validGetShortLivedRDPFile()
		input.TargetUser = ""
		input.VaultedAccountID = "10_10"
		requireVaultedAccountIDRule(t, input, "excluded_without")
	})

	malformed := map[string]string{
		"not_numeric":        "abc",
		"missing_separator":  "10",
		"missing_account_id": "10_",
		"missing_safe_id":    "_10",
		"negative":           "-1_5",
		"decimal":            "1.0_5",
		"too_many_parts":     "10_10_10",
		"leading_space":      " 10_10",
		"trailing_newline":   "10_10\n",
	}
	for name, vaultedAccountID := range malformed {
		vaultedAccountID := vaultedAccountID
		t.Run("malformed_vaulted_account_id_fails/"+name, func(t *testing.T) {
			input := validGetShortLivedRDPFile()
			input.VaultedAccountID = vaultedAccountID
			requireVaultedAccountIDRule(t, input, "regexp")
		})
	}
}
