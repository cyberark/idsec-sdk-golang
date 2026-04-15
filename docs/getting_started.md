---
title: Getting started
description: Getting started
---

# Getting started

## Installation

You can install the SDK via go modules. For private repositories, configure Git credentials:

```shell linenums="0"
export GOPRIVATE=1
git config --global url.\"https://<username>:<token>@github.com\".insteadOf \"https://github.com\"
go get github.com/cyberark/idsec-sdk-golang
```

## SDK Usage

The SDK supports [profiles](howto/working_with_profiles.md), which can be configured as needed and used for consecutive actions. See the [SDK examples](examples/sdk_examples.md) and [how to guides](howto/simple_sdk_workflow.md) for usage patterns.

For CLI usage and automation, see the [Idsec CLI](https://github.com/cyberark/idsec-cli-golang) documentation.
