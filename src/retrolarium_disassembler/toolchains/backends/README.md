# Processor language sources

These MIT-licensed source bundles contain the pinned upstream processor language
text, LICENSE and language credits only. The lock records each upstream URL,
commit, archive size and SHA-256 as well as the repacked bundle's hash and size.
No test ROMs, loaders, artwork or Gradle wrappers are included.

`tools/package_backends.py --archives PATH` recreates the bundles from the
verified original archives. ZIP timestamps, ordering and file modes are fixed.
Installation reads these bundles from the package, so GitHub regenerating an
upstream auto-archive cannot break an existing release's installation.
