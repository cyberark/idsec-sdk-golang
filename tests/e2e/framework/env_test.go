//go:build e2e

package framework

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEnvFile(t *testing.T) {
	const (
		fileOnlyKey = "IDSEC_E2E_FRAMEWORK_TEST_FILE_ONLY"
		presetKey   = "IDSEC_E2E_FRAMEWORK_TEST_PRESET"
	)

	tests := []struct {
		name     string
		contents *string
		wantErr  bool
		want     map[string]string
	}{
		{
			name:     "sets unset vars and keeps preset ones",
			contents: strPtr("# comment\n" + fileOnlyKey + "=from-file\n" + presetKey + "=from-file\n"),
			want:     map[string]string{fileOnlyKey: "from-file", presetKey: "from-shell"},
		},
		{
			name:     "missing file is ignored",
			contents: nil,
			want:     map[string]string{fileOnlyKey: "", presetKey: "from-shell"},
		},
		{
			name:     "malformed file returns error",
			contents: strPtr("NOT VALID LINE\n"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(fileOnlyKey, "")
			require.NoError(t, os.Unsetenv(fileOnlyKey))
			t.Setenv(presetKey, "from-shell")

			path := filepath.Join(t.TempDir(), ".env")
			if tt.contents != nil {
				require.NoError(t, os.WriteFile(path, []byte(*tt.contents), 0o600))
			}

			err := loadEnvFile(path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			for key, want := range tt.want {
				assert.Equal(t, want, os.Getenv(key), key)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
