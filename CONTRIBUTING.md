# Contributing

Thank you for considering contributing to "idsec-sdk-golang"! We welcome opening issues and requests to improve this project. For general contributions and community guidelines, please see the [repo](https://github.com/cyberark/community/).

## General Steps for opening issues

1. Open a new issue under "issues"
2. Pick the relevant issue type (Bug, Feature, Epic, etc.)
3. Fill in the issue template with as much detail as possible. This includes:
   - A clear description of the problem or feature request
   - Steps to reproduce the issue (if applicable)
   - Any relevant logs or screenshots
   - Your environment details (OS, version, etc.)

From here, your issue will be reviewed, and once you've responded to all feedback, we will provide the relevant code changes required.

## Development

### Unit Testing

We use comprehensive unit testing to ensure code quality and reliability. Follow these guidelines when writing tests:

#### Test File Organization
- Create test files alongside your source code using the convention `filename_test.go`
- Place package-specific test utilities, mocks, and fixtures in a `testutils` directory within your package
- For shared test resources across multiple packages, use the `testutils` directory in the appropriate parent package

#### Test Utilities Structure (`testutils`)
Organize your test utilities in a dedicated `testutils` directory within each package that requires testing support:

```
pkg/example/
├── example.go
├── example_test.go
└── testutils/
    ├── shared_mocks.go      # Mock implementations for external dependencies
    ├── test_helpers.go      # Helper functions for test setup and validation
    └── test_fixtures.go     # Test data, constants, and sample inputs
```

**File Purposes:**
- **`shared_mocks.go`** - Mock implementations of interfaces and external dependencies
- **`test_helpers.go`** - Utility functions for test setup, teardown, and common operations
- **`test_fixtures.go`** - Test data, sample inputs, expected outputs, and constants

**Usage in Tests:**
```go
import (
    "your-project/pkg/example/testutils"
)

func TestExample(t *testing.T) {
    // Use test fixtures
    input := testutils.SampleValidInput()

    // Use test helpers
    mockClient := testutils.NewMockClient()

    // Use shared mocks
    mockService := testutils.MockExternalService{}

    // ... rest of test
}
```

**Naming Conventions:**
- Use snake_case for test case names (e.g., `"success_case_normal_input"`, `"error_invalid_parameter"`)
- Prefix mock types with `Mock` (e.g., `MockHTTPClient`, `MockDatabase`)
- Prefix helper functions with descriptive verbs (e.g., `CreateTestUser()`, `SetupMockServer()`)
- Use clear, descriptive names for test fixtures (e.g., `ValidUserData`, `InvalidEmailFormat`)

#### Writing Tests
- Write tests using Go's [Table-Driven Tests](https://go.dev/wiki/TableDrivenTests) pattern for each function
- Include test cases for both success and failure scenarios
- Test edge cases and boundary conditions
- Use descriptive test names that clearly indicate what is being tested

#### Running Tests

```bash
# Run all unit tests with coverage reporting
make unit-test-all

# Run tests for specific packages
go test ./pkg/example/...

# Run tests with verbose output
go test -v ./...
```

#### Coverage Analysis
```bash
# Generate and view HTML coverage report
go tool cover -html=coverage.out
```

#### Test Requirements
- All new code must include comprehensive unit tests
- Maintain or improve overall test coverage
- Tests must pass before submitting pull requests
- Mock external dependencies appropriately

### Using GitHub Copilot for Testing

This project includes comprehensive GitHub Copilot instructions to help you write consistent, high-quality tests efficiently.

#### Copilot Instructions File
The [`.github/copilot-instructions.md`](.github/copilot-instructions.md) file contains detailed standards for:
- Documentation format and requirements
- Table-driven test structure and patterns
- Code quality standards and error handling
- Test organization and mocking strategies
- Project-specific patterns and conventions

### Function Documentation

All exported functions, types, constants, and variables must have comprehensive documentation comments following Go's documentation standards.

#### Documentation Format
Follow this structured format for all exported functions:

```go
// FunctionName describes what the function does in one line.
//
// Provide a detailed description of the function's behavior, including any important
// details about its implementation or usage patterns.
//
// Parameters:
//   - param1: Description of the parameter and its expected values
//   - param2: Description of the parameter and its constraints
//   - param3: Optional parameter description (use "nil for no limit" style)
//
// Returns description of what the function returns, including error conditions.
//
// Example:
//   result, err := FunctionName(
//       "example input",
//       42,
//       &optionalParam,
//   )
//   if err != nil {
//       // handle error
//   }
func FunctionName(param1 string, param2 int, param3 *int) (ResultType, error) {
```

#### Documentation Requirements
- **Start with the exact name**: Begin comments with the exact name of the item being documented
- **One-line summary**: First line should be a complete sentence describing what the function does
- **Detailed description**: Provide context about behavior, implementation details, or usage patterns
- **Parameter documentation**: Document all parameters with their types, constraints, and expected values
- **Return value documentation**: Explain what is returned, including all error conditions
- **Examples**: Include usage examples for complex functions
- **Consistent terminology**: Use the same terms throughout the codebase

#### Package Documentation
- Add package documentation at the top of the main package file
- Start with "Package [name] provides..."
- Describe the main purpose and functionality

#### Documentation Best Practices
- Use complete sentences with proper punctuation
- Explain what the function does, not how it works (unless the how is important)
- Be specific about constraints and expected inputs
- Document any side effects or state changes
- Include examples that can be copy-pasted and run
- Keep documentation up-to-date with code changes

### CLI command guidelines

To maintain a consistent and predictable user experience across the IDSec SDK, all CLI commands must adhere to the following structural and naming conventions.

#### 1. General Structure
The command hierarchy is strictly defined as **Service** → **Resource** → **Action**.

**Syntax:**
```bash
idsec <service> <resource> <action> [flags/parameters]
```

**Definitions:**
* **Service:** The high-level product or domain (e.g., `pcloud`, `cmgr`).
* **Resource:** The specific entity being manipulated (e.g., `safes`, `networks`, `pools`). Plural nouns are preferred for resources.
* **Action:** The operation to perform on the resource (e.g., `create`, `list`, `delete`).

#### 2. Resource & Action Separation (Avoid "Stuttering")
Do not repeat the resource name inside the action name. The context is provided by the resource command that precedes it.

* **Bad:** `idsec pcloud safes create-safe` (Redundant)
* **Good:** `idsec pcloud safes create` (Clean)

#### 3. Standard Actions & Verbs
To prevent confusion (e.g., users guessing between "remove", "delete", or "destroy"), use the following standard verbs for common CRUD operations.

| Intent | Canonical Verb | Accepted Aliases | Description |
| :--- | :--- | :--- | :--- |
| **Create** | `create` | `add` | Creates a new resource. |
| **Read Many** | `list` | `ls` | Returns a list of resources. Should support filtering. |
| **Read One** | `get` | `read` | Returns details of a specific resource. Usually requires an ID or name. |
| **Update** | `update` | `edit` | Modifies an existing resource. |
| **Delete** | `delete` | `rm` | Permanently removes a resource. |

#### 4. Examples

**Creating a Safe:**
```bash
# Correct
idsec pcloud safes create --safe-name="MySafe"

# Incorrect (Redundant naming)
idsec pcloud safes create-safe --safe-name="MySafe"
```

**Listing connector pools:**
```bash
# Correct
idsec cmgr pools list

# Incorrect (Wrong hierarchy)
idsec cmgr list-pools
```

## Releases

**Maintainers only** should create releases. Follow these steps to prepare for a release:

### Pre-requisites

- Review recent commits and ensure the changelog includes all relevant changes, with references to GitHub issues or PRs when applicable.
- Verify that any updated dependencies are accurately reflected in the `NOTICES`.
- Confirm that the required documentation is complete and has been approved.

### Legal

Any submission of work, including any issue, request, modification of, or addition to, an existing work ("Contribution") to "idsec-sdk-golang" shall be governed by and subject to the terms of the Apache License 2.0 (the
"License") and to the following complementary terms. In case of any conflict or inconsistency between the provision of the License and the complementary terms, the complementary terms shall prevail. By submitting the Contribution, you represent and warrant that the Contribution is your original creation and you own all right, title and interest in the Contribution. You represent that you are legally entitled to grant the rights set out in the License and herein, without violation of, or conflict with, the rights of any other party. You represent that your Contribution includes complete details of any third-party license or other restriction associated with any part of your Contribution of which you are personally aware.
