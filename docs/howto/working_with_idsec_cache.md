---
title: Work with Idsec cache
description: Working With Idsec Cache
---

# Work with Idsec cache

Both the CLI and SDK cache login information in the local machine's keystore or, when a keystore does not exist, in an encrypted folder (located in `$HOME/.idsec_cache`). The cached information is used to run commands until the authentication tokens expire or are otherwise invalided.

You can set the cache folder with the `IDSEC_KEYRING_FOLDER` env variable. To force Idsec SDK to work only with the filesystem cache, use the `IDSEC_BASIC_KEYRING` environment variable

If you want to ignore the cache when logging in, use the `-f` flag:
``` bash  linenums="0"
idsec login --force
```

To clear the cache, run `idsec cache clear` or, when using an encrypted folder, remove the files from the `$HOME/.idsec_cache` folder.
