---
title: Work with Idsec cache
description: Working With Idsec Cache
---

# Work with Idsec cache

The SDK caches login information in the local machine's keystore or, when a keystore does not exist, in an encrypted folder (located in `$HOME/.idsec/cache/keyring`), where the cached entries are kept in a single file. The cached information is used until the authentication tokens expire or are otherwise invalidated.

You can set the cache folder with the `IDSEC_KEYRING_FOLDER` environment variable. To force the SDK to work only with the filesystem cache, use the `IDSEC_BASIC_KEYRING` environment variable. The key material that protects the encrypted folder is kept in a separate file outside that folder, located by default in `$HOME/.idsec/keys/keyring.key` and readable only by its owner. You can set its path with the `IDSEC_KEYRING_KEY_FILE` environment variable; the two locations are set independently, and `IDSEC_KEYRING_FOLDER` does not relocate the key file.

To clear the cache when using an encrypted folder, remove the files from the `$HOME/.idsec/cache/keyring` folder, or remove the key file, which invalidates the cache as well. In both cases the SDK discards the cache and authenticates again on its next use, as it also does for a cache written by an earlier SDK version, so no error is reported and no action is needed after an upgrade. For CLI cache management commands, see the [Idsec CLI documentation](https://github.com/cyberark/idsec-cli-golang).
