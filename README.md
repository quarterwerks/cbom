# CBOM crypto inventory skill

This repository contains the `crypto-inventory` skill for generating a CBOM-style inventory of cryptographic libraries, protocols, and algorithms used by a repository.

## Contents

- `skill/crypto-inventory/` — the installable skill, scanner, and agent metadata.
- `sample-results/webgoat-crypto-inventory.json` — a sample scan of the open-source [OWASP WebGoat](https://github.com/WebGoat/WebGoat) project.

## Run the scanner

The scanner uses only Python’s standard library:

```bash
python3 skill/crypto-inventory/scripts/scan_crypto.py \
  /path/to/repository \
  --output /path/to/repository/crypto-inventory.json
```

The result records relative evidence paths, matching lines, detected manifests, and confidence levels. It is evidence gathering, not a proof that a project’s cryptography is secure or complete. Results can miss generated or vendored code, binaries, dynamically loaded libraries, and unsupported package ecosystems.

## Sample

The WebGoat sample was generated from WebGoat commit `7517acc` at scan time. Re-run the command against a fresh WebGoat checkout to produce an updated result; findings may change as WebGoat evolves.
