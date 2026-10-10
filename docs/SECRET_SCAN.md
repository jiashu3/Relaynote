# Packaging and secret scan

Source allowlist inspected on 2026-10-10. 30 source/document/build files scanned before this report was added. No private-key material, common credential patterns, runtime database/token/certificate files or copied handoff/conversation material found. Known private environment/host references were absent.

The release source excludes binaries, toolchains, caches, state, original handoff material and previous project archives. Tests use synthetic identities and generate temporary test certificates at runtime; no real credentials are included. This focused scan is not a guarantee against every secret format. Executable hashes and architecture/runtime labels are in BUILD_MANIFEST.json. The mock example is echo-only, contained in one local process, and explicitly labelled mock-only.
