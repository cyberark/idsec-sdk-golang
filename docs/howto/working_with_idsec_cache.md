---
title: Work with Idsec cache
description: Working With Idsec Cache
---

# Work with Idsec cache

The SDK caches login information in the local machine's keystore or, when a keystore does not exist, in an encrypted folder (located in `$HOME/.idsec/cache`). The cached information is used until the authentication tokens expire or are otherwise invalidated.

You can set the cache folder with the `IDSEC_KEYRING_FOLDER` environment variable. To force the SDK to work only with the filesystem cache, use the `IDSEC_BASIC_KEYRING` environment variable.

To clear the cache when using an encrypted folder, remove the files from the `$HOME/.idsec/cache` folder. For CLI cache management commands, see the [Idsec CLI documentation](https://github.com/cyberark/idsec-cli-golang).
