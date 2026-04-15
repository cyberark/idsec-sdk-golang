# E2E Framework Quick Start

Get started with E2E testing in 5 minutes.

## Step 1: Set Environment Variables

The framework supports **multiple authenticators** simultaneously. Configure the profiles you have credentials for:

### Both ISP and PVWA (recommended -- runs all tests)

```bash
# ISP credentials
export IDSEC_E2E_ISP_USERNAME="serviceuser@tenant.cyberark.cloud.12345"
export IDSEC_E2E_ISP_SECRET="your_isp_secret"

# PVWA credentials
export IDSEC_E2E_PVWA_USERNAME="your_pvwa_username"
export IDSEC_E2E_PVWA_SECRET="your_pvwa_password"
export IDSEC_E2E_PVWA_URL="https://pvwa.example.com"
```

### ISP-only

```bash
export IDSEC_E2E_ISP_USERNAME="serviceuser@tenant.cyberark.cloud.12345"
export IDSEC_E2E_ISP_SECRET="your_isp_secret"
# Optional: export IDSEC_E2E_ISP_AUTH_METHOD="identity_service_user"
```

### PVWA-only

```bash
export IDSEC_E2E_PVWA_USERNAME="your_pvwa_username"
export IDSEC_E2E_PVWA_SECRET="your_pvwa_password"
export IDSEC_E2E_PVWA_URL="https://pvwa.example.com"
# Optional: export IDSEC_E2E_PVWA_LOGIN_METHOD="ldap"
```

> **Tip:** Set `IDSEC_E2E_AUTH_EXPECT` to enforce which profiles must be present.
> For example, `IDSEC_E2E_AUTH_EXPECT=isp,pvwa` fails if either is missing (useful for CI).
> Default is `all`, which builds every profile that has credentials and skips the rest.

<details>
<summary>Legacy variables (deprecated)</summary>

The old single-auth variables are still supported for backward compatibility:

```bash
export IDSEC_E2E_USERNAME="your-user@tenant.cyberark.cloud.12345"
export IDSEC_E2E_SECRET="your-secret"
export IDSEC_E2E_AUTH_METHOD="identity_service_user"
```

These are automatically mapped to the corresponding provider when the new prefixed variables are not set. However, legacy variables only configure **one** authenticator -- use the prefixed variables above to run both ISP and PVWA tests together.

</details>

## Step 2: Run Existing Tests

```bash
# Run all E2E tests
go test -tags=e2e -v ./tests/e2e/...
```

Expected output:
```
=== RUN   TestListConnectors
    connectors_test.go:XX: isp authenticator created and authenticated
    connectors_test.go:XX: pvwa authenticator created and authenticated
    connectors_test.go:XX: E2E test context initialized successfully
    connectors_test.go:XX: ============================================================
    connectors_test.go:XX:   Test: List SIA Connectors
    connectors_test.go:XX: ============================================================
    connectors_test.go:XX: Listing SIA connectors...
    connectors_test.go:XX: Found 0 connector(s)
--- PASS: TestListConnectors (2.34s)
```

## Step 3: Write Your First Test

Create `tests/e2e/myservice/mytest_test.go`:

```go
//go:build e2e

package myservice

import (
    "testing"
    "github.com/stretchr/testify/require"
    myservice "github.com/cyberark/idsec-sdk-golang/pkg/services/myservice"
    "github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

func TestMyFeature(t *testing.T) {
    framework.Run(t, func(ctx *framework.TestContext) {
        // Get service
        service, err := ctx.API.MyService()
        require.NoError(t, err)

        // Test something
        result, err := service.ListItems()
        require.NoError(t, err)
        require.NotNil(t, result)
    }, myservice.ServiceConfig)
}
```

## Step 4: Run Your Test

```bash
go test -tags=e2e -v ./tests/e2e/myservice/
```

## Common Patterns

### Create and Delete Resource

```go
func TestCreateResource(t *testing.T) {
    framework.Run(t, func(ctx *framework.TestContext) {
        service, _ := ctx.API.MyService()

        // Create with unique name
        name := framework.RandomResourceName("e2e-test")
        resource, err := service.Create(name)
        require.NoError(t, err)

        // Register cleanup
        ctx.TrackResourceByType("MyResource", resource.ID, func() error {
            return service.Delete(resource.ID)
        })

        // Test the resource
        // ... cleanup happens automatically
    }, myservice.ServiceConfig)
}
```

### Wait for Async Operation

```go
err := framework.WaitForCondition(
    30*time.Second,  // timeout
    2*time.Second,   // interval
    func() (bool, error) {
        status, err := service.GetStatus(id)
        if err != nil {
            return false, err
        }
        return status == "ready", nil
    },
)
require.NoError(t, err)
```

## Troubleshooting

**Tests are skipped:**
```bash
# Check environment variables
env | grep IDSEC_E2E

# Tests skip when a service requires an authenticator that isn't configured.
# For example, PVWA-only tests skip when only ISP credentials are set.
# Configure both profiles, or set IDSEC_E2E_AUTH_EXPECT to run specific ones.
```

**Authentication fails:**
```bash
# Verify credentials are set for the correct profile
env | grep IDSEC_E2E_ISP   # ISP profile vars
env | grep IDSEC_E2E_PVWA  # PVWA profile vars

# If using legacy variables, make sure new-style vars aren't also set
# (new-style takes precedence)
```

**Can't find tests:**
```bash
# Make sure you use the -tags flag
go test -tags=e2e ./tests/e2e/...
#         ^^^^^^^^^^^^ Required!
```

**CI requires all auth types but one is missing:**
```bash
# If IDSEC_E2E_AUTH_EXPECT=isp,pvwa and one set of credentials is missing,
# the test will FAIL (not skip). This is intentional -- it ensures CI has
# all expected credentials configured. Fix by providing the missing vars.
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Look at [tests/e2e/sia/connectors_test.go](sia/connectors_test.go) for examples
- Check [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) for architecture details

## Tips

1. Use `framework.Run()` to handle context, auth checks, and cleanup
2. Use `framework.RandomResourceName()` for unique names
3. Register cleanup for every resource you create
4. Use `framework.LogSection()` to organize test output
5. Add service auth configs to `framework.Run()` when applicable


