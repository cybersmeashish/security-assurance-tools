# Contribution 001 — Evidence Bundle Checker

**Runnable original tool, 24 November 2026.** A security claim should link to an inspectable artifact. Before admitting a review bundle, check that its files match a bounded, explicit manifest.

## What this tool does

The [CLI](../tools/bundle_checker.py) validates manifest shape, unique relative paths, SHA-256 digests, regular files and size limits. It rejects traversal, absolute paths, symlinks, missing artifacts, duplicate JSON keys and oversized files. The sample contains only a synthetic text result. It never executes a bundle or decompresses an archive.

```sh
docker --context orbstack exec security-assurance-tools-dev python tools/bundle_checker.py fixtures/bundle fixtures/manifest.json
```

Exit 0 means the accepted files match the supplied manifest. Exit 2 means invalid input, inaccessible data or a digest mismatch. Results are JSON, with `authenticity_established=false` deliberately visible.

## Why separate integrity from authority

An attacker who controls both a file and its unsigned manifest can produce matching hashes. A match does not authenticate an author, prove a measurement was performed, establish completeness or certify a control. Use a separately trusted manifest/signature channel and accountable review before making those claims. This first contribution implements byte/path checks, not that trust system.

The checker also assumes an owned, stable directory while files are read. It does not provide a race-proof filesystem sandbox for adversarial concurrent writes. Unlisted files are not certified by the tool. The caller must define which artifact set is required; a short manifest can omit a failed experiment.

## Actual experiment

[Results](../evidence/results.json) show the sample matching its digest and the same sample failing against a changed expected digest. Regression tests exercise important denied cases, including a symlink and path traversal. [Verification](../evidence/verification.json) records the exact source hashes and isolated runtime. These checks are not evidence that any enterprise bundle is signed or truthful.

## Integration contract

Use a disposable, bounded input directory. Obtain the expected manifest through the approved review process. Fail admission on malformed input or mismatch; do not “repair” a manifest to match untrusted files. Preserve the submitted manifest and original result for audit. Give the caller an explicit result rather than suppressing missing files.

A future version can add trusted signature verification, required-artifact schemas, independent execution receipts and content-specific checks. Each addition needs its own negative cases and trust assumptions. Avoid expanding a small checker into an unreviewed package execution service.

This tool supports the broader [research/evidence portfolio](https://github.com/cybersmeashish/security-research-and-assessments). Its original source is MIT-licensed; upstream standards and linked projects retain their own terms.
