# Release Compatibility

HuntProxy 0.2.0 embeds the first-party plugin catalog from commit `d4e1aa3`. Setup and updates install that immutable snapshot, so a working installation does not depend on the current state or availability of this repository.

| Plugin ID | Version bundled with HuntProxy 0.2.0 | Compatibility note |
| --- | ---: | --- |
| `403-bypasser` | 0.6.1 | Plugin API v1 |
| `auth-analyzer` | 1.4.2 | Plugin API v1 |
| `cache-analyzer` | 0.15.0 | Plugin API v1 |
| `csrf-analyzer` | 1.5.2 | Plugin API v1 |
| `ip-rotate` | 1.1.1 | Plugin API v1; requires its documented AWS setup |
| `jwt-analyzer` | 1.3.4 | Plugin API v1 |
| `param-finder` | 0.7.0 | Plugin API v1 |
| `racer` | 0.6.4 | Required for HuntProxy 0.2.0; older Racer versions are blocked |
| `request-smuggler` | 1.4.9 | Plugin API v1 |
| `upload-analyzer` | 1.3.4 | Plugin API v1 |

HuntProxy owns an installed first-party package only while its files match a known bundled snapshot. An unchanged package is upgraded automatically. A package with local changes is preserved so an update cannot overwrite user work. Custom plugins with other IDs are outside this catalog and are not subject to the Racer compatibility guard.

If HuntProxy reports that a preserved Racer package is incompatible, stop HuntProxy, move that package out of `~/.huntproxy/plugins`, and restart HuntProxy to install Racer 0.6.4. Then reapply the changes you still need. Validate the resulting package before use:

```bash
node scripts/validate-plugin.mjs /path/to/racer
```

The compatibility matrix describes the exact versions reviewed and shipped with the core release. Development checkouts can still be loaded through an absolute `plugin_dir` in HuntProxy configuration.
