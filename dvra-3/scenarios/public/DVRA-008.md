# DVRA-008 — Bundle extraction path traversal

The artifact service extracts a compact bundle into a per-job directory. The
vulnerable route joins an archive-controlled path to that directory and writes it
without validating path components.

The dangerous route is acknowledgement-gated because a crafted path can write
outside the intended job directory. Use only the disposable container profile.

## Goal

- Demonstrate a cross-job overwrite through `../` path traversal.
- Trace the path from the HTTP body to the filesystem write.
- Explain why `PathBuf::join` is not a containment check.
- Compare the vulnerable route with the lexical path validation used by the
  fixed route.
- State the remaining symlink assumption explicitly: the destination tree is
  provisioned by the trusted runtime and is not tenant-writable before extraction.
