# E2E Testing

End-to-end tests for the IDSEC SDK using the E2E testing framework.

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for detailed getting started guide.

### Running Tests

```bash
# --- Option 1: Multi-auth (recommended) ---
# Configure both ISP and PVWA credentials so all tests run:
export IDSEC_E2E_ISP_USERNAME="serviceuser@tenant.cyberark.cloud.12345"
export IDSEC_E2E_ISP_SECRET="your_isp_secret"
export IDSEC_E2E_PVWA_USERNAME="your_pvwa_username"
export IDSEC_E2E_PVWA_SECRET="your_pvwa_password"
export IDSEC_E2E_PVWA_URL="https://pvwa.example.com"

# --- Option 2: ISP-only ---
export IDSEC_E2E_AUTH_EXPECT=isp
export IDSEC_E2E_ISP_USERNAME="serviceuser@tenant.cyberark.cloud.12345"
export IDSEC_E2E_ISP_SECRET="your_isp_secret"

# --- Option 3: PVWA-only ---
export IDSEC_E2E_AUTH_EXPECT=pvwa
export IDSEC_E2E_PVWA_USERNAME="your_pvwa_username"
export IDSEC_E2E_PVWA_SECRET="your_pvwa_password"
export IDSEC_E2E_PVWA_URL="https://pvwa.example.com"

# Run all E2E tests
go test -tags=e2e -v ./tests/e2e/...

# Run specific package
go test -tags=e2e -v ./tests/e2e/pcloud/

# Run regular Identity authentication/refresh tests
IDSEC_E2E_AUTH_EXPECT=isp \
IDSEC_E2E_ISP_AUTH_METHOD=identity \
go test -tags=e2e -v ./tests/e2e/auth/

# Run Identity service-user authentication/refresh tests
IDSEC_E2E_AUTH_EXPECT=isp \
IDSEC_E2E_ISP_AUTH_METHOD=identity_service_user \
go test -tags=e2e -v ./tests/e2e/auth/
```

The proactive-refresh test seeds a copied token inside the 60-second expiration
grace window and runs cache operations in a helper subprocess with a unique
basic-keyring directory. This keeps its environment isolated from other E2E
packages and allows parent tests to run in parallel safely. The reactive 401
test invalidates only a read-only service client's bearer and cookies; its
refresh callback restores authentication and retries the request. Additional
tests verify proactive refresh from in-memory state with caching disabled and a
401 callback that performs real token renewal before retrying.

### Triggering E2E Tests on a Pull Request

The E2E pipeline is opt-in. After pushing a commit that changes E2E tests or
behavior requiring E2E validation, add this exact comment to the pull request:

```text
#run_e2e_tests
```

Agents updating such a pull request should post the comment after the relevant
commit is pushed. A documentation-only change does not require an E2E trigger.

After posting the trigger:

1. Record the pushed commit SHA and wait four minutes before the first status check.
2. Read the pull request's commit statuses and verify the response is for that SHA.
3. Inspect the `ci/jenkins-e2e` context specifically. Do not use the aggregate
   commit state because unrelated checks can fail independently.
4. While `ci/jenkins-e2e` is pending, poll the commit statuses every 30 seconds.
5. Stop when that context reports success or failure, or after 12 minutes total.

### Retrying Fragile E2E Runs

E2E tests depend on live services and can fail because of transient environment
instability. A failed `ci/jenkins-e2e` run may be retried up to three times by
posting `#run_e2e_tests` again. Wait five minutes after each failed run before
posting the next trigger, then use the polling procedure above for the rerun.

Stop after three retries and report the failure. A repeated failure in the same
test should be investigated rather than treated as environment instability.

## Generating New Tests

Use the `gene2e` tool to quickly scaffold new E2E tests:

### Using Makefile

```bash
# Generate a new test
make gene2e SERVICE=pcloud/accounts NAME=CreateAccount

# Preview without creating file
make gene2e-preview SERVICE=sia/connectors NAME=ListConnectors
```

### Using go run

```bash
# Generate test
go run ./tools/gene2e -service=pcloud/accounts -name=CreateAccount

# Preview (dry-run)
go run ./tools/gene2e -service=sia/connectors -name=ListConnectors -dry-run
```

### What Gets Generated

The tool creates a test skeleton with:
- Correct `//go:build e2e` tag
- Framework.Run wrapper for context/auth/cleanup
- Service getter
- Cleanup pattern with TODO comments
- Test structure ready to fill in

### Example

```bash
make gene2e SERVICE=pcloud/safes NAME=CreateAndDeleteSafe
```

Creates `tests/e2e/pcloud/createanddeletesafe_test.go`:

```go
//go:build e2e

package pcloud

import (
	"testing"
	"github.com/stretchr/testify/require"
	safes "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

func TestCreateAndDeleteSafe(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create And Delete Safe")

		svc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		// TODO: Create resource
		// TODO: Register cleanup
		// TODO: Add test assertions
	}, safes.ServiceConfig)
}
```

Then edit the file and fill in the TODO sections with your test logic.

## Authentication

### Multi-Auth (Default)

By default the framework builds **all authenticators** whose credentials are present in the environment. This means ISP-requiring tests and PVWA-requiring tests can run together in a single `go test` invocation -- no more skipping half the suite.

Each service declares which authenticator(s) it needs (e.g., `isp`, `pvwa`, or either). The framework matches available authenticators to service requirements at runtime. A test is only skipped when its required authenticator was not configured.

### `IDSEC_E2E_AUTH_EXPECT`

The `IDSEC_E2E_AUTH_EXPECT` environment variable controls which authenticators the framework expects to be available.

| Value             | Behavior |
| ----------------- | -------- |
| `all` *(default)* | Build every provider whose env vars are present. No error if some providers have no credentials. At least one must succeed. |
| `isp`             | Only build ISP. Error if ISP credentials are missing. |
| `pvwa`            | Only build PVWA. Error if PVWA credentials are missing. |
| `isp,pvwa`        | Build both. Error if **either** set of credentials is missing. |

When set to a specific list, missing credentials for a listed provider is a **hard error** (test fails), not a skip. This gives CI the ability to enforce that all expected auth types are configured.

### Auth Provider Environment Variables

**ISP auth profile:**

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `IDSEC_E2E_ISP_USERNAME` | Yes | — | ISP username (e.g., `user@tenant.cyberark.cloud.12345`) |
| `IDSEC_E2E_ISP_SECRET` | Yes | — | ISP service user secret or password |
| `IDSEC_E2E_ISP_AUTH_METHOD` | No | `identity_service_user` | Auth method: `identity_service_user` or `identity` |
| `IDSEC_E2E_ISP_IDENTITY_URL` | No | — | Override for the Identity URL |
| `IDSEC_E2E_ISP_IDENTITY_TENANT_SUBDOMAIN` | No | — | Identity tenant subdomain |

**PVWA auth profile:**

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `IDSEC_E2E_PVWA_USERNAME` | Yes | — | PVWA username |
| `IDSEC_E2E_PVWA_SECRET` | Yes | — | PVWA password |
| `IDSEC_E2E_PVWA_URL` | Yes | — | PVWA base URL (e.g., `https://pvwa.example.com`) |
| `IDSEC_E2E_PVWA_LOGIN_METHOD` | No | `ldap` | Login method: `cyberark`, `ldap`, or `windows` |

**General:**

| Variable | Required | Default | Description |
| -------- | -------- | ------- | ----------- |
| `IDSEC_E2E_AUTH_EXPECT` | No | `all` | Which auth profiles to expect (see table above) |
| `IDSEC_E2E_SKIP` | No | `false` | Set to `true` to skip all E2E tests |

### Backward Compatibility

The legacy environment variables (`IDSEC_E2E_AUTH_METHOD`, `IDSEC_E2E_USERNAME`, `IDSEC_E2E_SECRET`) are still supported for existing CI pipelines and local setups. The framework applies backward-compatible mapping when the new prefixed variables are **not** set:

| Legacy Variables | Mapped To |
| ---------------- | --------- |
| `IDSEC_E2E_AUTH_METHOD=identity*` + `USERNAME/SECRET` | ISP provider config |
| `IDSEC_E2E_AUTH_METHOD=pvwa` + `USERNAME/SECRET/PVWA_URL` | PVWA provider config |

If **both** legacy and new-style variables are set, the new prefixed variables take precedence.

> **Note:** The legacy variables only configure a single authenticator. To run both ISP and PVWA tests together, use the new prefixed variables.

### Adding a New Auth Type

The framework uses a provider registry pattern. To add a new auth type (e.g., `oauth`):

1. Create a config struct implementing `AuthProviderConfig`
2. Write a `Load()` function that reads `IDSEC_E2E_OAUTH_*` env vars
3. Write an `Authenticate()` function that creates and authenticates the new type
4. Call `RegisterAuthProvider()` in the `init()` of `auth_providers.go`

No changes needed in `config.go`, `context.go`, or any test files.

## Framework Documentation

The E2E framework provides:
- **Multi-auth support** - configures ISP, PVWA, or both simultaneously
- **Automatic authentication** - handles ISP/Identity and PVWA auth via provider registry
- **Cleanup management** - LIFO resource cleanup
- **Test utilities** - random names, wait conditions, retries
- **Configuration** - environment-based setup with backward compatibility

See [framework/](framework/) for framework source code.

## Test Organization

```
tests/e2e/
├── framework/                # E2E framework core
│   ├── auth_providers.go    # Auth provider registry (ISP, PVWA, extensible)
│   ├── context.go           # Test context & multi-auth creation
│   ├── cleanup.go           # LIFO cleanup stack
│   ├── config.go            # Environment configuration
│   └── utils.go             # Test utilities
├── pcloud/                  # PCloud service tests
├── sia/                     # SIA service tests
├── identity/                # Identity service tests
└── main_test.go             # Test suite entry point
```

## Best Practices

### Context Setup

1. **Use `framework.Run()`** to handle context, auth checks, and cleanup
2. **Use `framework.RandomResourceName()`** for unique resource names to avoid conflicts

### Cleanup (Critical)

3. **Register cleanup for every resource** you create using `ctx.TrackResourceByType()`
4. **Use LIFO order** - cleanup registration order matters; resources are deleted in reverse order

**Cleanup Example:**

```go
func TestExample(t *testing.T) {
    framework.Run(t, func(ctx *framework.TestContext) {
        // Create parent resource first
        safe, _ := safesSvc.Create(...)
        ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
            return safesSvc.Delete(...)  // Deleted LAST (LIFO)
        })

        // Create child resource second
        account, _ := accountsSvc.Create(...)
        ctx.TrackResourceByType("Account", account.AccountID, func() error {
            return accountsSvc.Delete(...)  // Deleted FIRST (LIFO)
        })

        // Test assertions...
        // Cleanup happens automatically in reverse order:
        // 1. Account deleted first
        // 2. Safe deleted last
    }, safes.ServiceConfig, accounts.ServiceConfig)
}
```

**Note:** Cleanup failures are now tracked and reported. If any cleanup fails, the test will be marked as failed with details about which resources could not be cleaned up.

See [QUICKSTART.md](QUICKSTART.md) for a 5-minute getting started guide.
