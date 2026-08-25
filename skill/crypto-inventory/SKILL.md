---
name: crypto-inventory
description: Scan a repository containing one or more projects, inspect dependency manifests and source code, and generate a JSON inventory of cryptographic libraries, protocols, and algorithms with per-project evidence. Use when asked to inventory cryptography, prepare a CBOM-style report, identify crypto dependencies, or analyze cryptographic usage across a target repository.
---

# Crypto Inventory

Use the bundled scanner to produce a repeatable inventory. Treat the result as evidence gathering, not a proof that cryptography is secure or complete.

## Workflow

1. Identify the target repository root. Do not scan outside it.
2. Run `scripts/scan_crypto.py TARGET_REPO --output TARGET_REPO/crypto-inventory.json`.
3. Review the JSON for projects, dependency evidence, source evidence, protocols, and algorithms.
4. Report scan limitations, especially generated code, vendored code, binaries, dynamic loading, and unsupported package ecosystems.

The scanner skips version-control metadata, virtual environments, dependency caches, build output, and common generated directories. It detects projects from dependency manifests and source roots; a project may be the repository root or a nested directory.

## Output

The JSON contains:

- `schema_version`, `generated_at`, `repository`, and `scan` metadata.
- `projects`, each with a relative `path`, detected `languages`, `manifests`, and `crypto` findings.
- Findings grouped as `libraries`, `protocols`, and `algorithms`.
- Each finding includes `name`, `evidence` (`file`, `line`, `source`, and `match`), and `confidence`.

Keep evidence paths relative to the target repository. Do not invent findings when a dependency or source match is ambiguous; retain the evidence and use lower confidence.

## Direct invocation

```bash
python3 scripts/scan_crypto.py /path/to/repository \
  --output /path/to/repository/crypto-inventory.json
```

Use `--include` to add explicitly named directories otherwise skipped, and `--max-file-bytes` to control source-file limits. The script uses only the Python standard library.
