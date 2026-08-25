#!/usr/bin/env python3
"""Inventory cryptographic libraries, protocols, and algorithms in a repository."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "vendor",
    "target", "build", "dist", "out", "coverage", ".tox", "__pycache__",
    ".gradle", ".idea", ".next", ".terraform", "Pods",
}
MANIFESTS = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "pubspec.yaml",
    "Package.swift", "mix.exs", "mix.lock",
}
SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx",
    ".kt", ".m", ".mm", ".php", ".py", ".rb", ".rs", ".scala", ".swift",
    ".ts", ".tsx", ".ex", ".exs", ".sol", ".dart", ".tf", ".yaml", ".yml",
}

LIBRARIES = {
    "OpenSSL": r"\b(?:openssl|libssl|libcrypto)\b",
    "BoringSSL": r"\bboringssl\b", "LibreSSL": r"\blibreSSL\b",
    "libsodium": r"\blibsodium|sodium\.h|sodiumoxide\b", "Botan": r"\bbotan(?:-\d+)?\b",
    "GnuTLS": r"\bgnutls\b", "wolfSSL": r"\b(?:wolfssl|cyassl)\b",
    "mbed TLS": r"\bmbed(?:tls|crypto|x509)\b",
    "PyCA cryptography": r"\b(?:cryptography\.hazmat|from\s+cryptography\s+import)\b",
    "PyCryptodome": r"\b(?:Crypto\.|Cryptodome\.)\b",
    "JCA/JCE": r"\b(?:javax?\.crypto|java\.security\.(?:MessageDigest|Signature|KeyStore))\b",
    "Microsoft .NET cryptography": r"\bSystem\.Security\.Cryptography\b",
    "Node.js crypto": r"(?:require\(['\"]crypto['\"]\)|from\s+['\"](?:node:)?crypto['\"]|crypto\.(?:create|subtle))",
    "Web Crypto API": r"\b(?:crypto\.subtle|window\.crypto|globalThis\.crypto)\b",
    "Go crypto packages": r"\b(?:crypto/(?:aes|cipher|des|ecdh|ecdsa|ed25519|elliptic|hmac|md5|rand|rsa|sha\d*|tls|x509)|golang\.org/x/crypto)\b",
    "RustCrypto": r"\b(?:RustCrypto|sha2::|aes::|ring::|rustls::|rustls)\b",
    "ring": r"\bring::|['\"]ring['\"]", "rustls": r"\brustls(?:::|['\"])\b",
    "secp256k1": r"\bsecp256k1\b", "Tink": r"\bgoogle\.tink|\btink\b",
    "NaCl": r"\b(?:NaCl|tweetnacl|nacl)\b",
}
PROTOCOLS = {
    "TLS": r"\bTLS(?:v?1(?:\.0|\.1|\.2|\.3)?)?\b|\bssl(?:v?\d)?\b",
    "DTLS": r"\bDTLS(?:v?1(?:\.0|\.2|\.3)?)?\b", "SSH": r"\bSSH(?:-\d(?:\.\d)?)?\b|\blibssh\b|\bparamiko\b",
    "HTTPS": r"\bhttps://|\bHTTPS\b", "IPsec": r"\bIPsec\b|\bIKEv?[12]\b",
    "QUIC": r"\bQUIC\b|\bquic-go\b", "WireGuard": r"\bWireGuard\b",
    "S/MIME": r"\bS/MIME\b", "OpenPGP": r"\b(?:OpenPGP|PGP|GnuPG|gpg)\b",
    "JOSE": r"\b(?:JWT|JWS|JWE|JOSE)\b", "OAuth 2.0": r"\bOAuth\s*2(?:\.0)?\b",
    "mTLS": r"\bmTLS\b|mutual\s+TLS",
}
ALGORITHMS = {
    "AES": r"\bAES(?:-?(?:128|192|256))?(?:-?(?:GCM|CCM|CBC|CTR|ECB|XTS))?\b",
    "ChaCha20-Poly1305": r"\bChaCha20(?:-Poly1305)?\b", "3DES": r"\b(?:3DES|Triple\s*DES|DESede)\b",
    "DES": r"(?<!3)\bDES\b", "RSA": r"\bRSA(?:-?(?:1024|2048|3072|4096))?\b",
    "ECDSA": r"\bECDSA\b", "EdDSA/Ed25519": r"\b(?:EdDSA|Ed25519|Ed448)\b",
    "ECDH/X25519": r"\b(?:ECDH|X25519|X448)\b", "Diffie-Hellman": r"\b(?:Diffie[- ]Hellman|DH)\b",
    "SHA-1": r"\b(?:SHA[- ]?1|SHA1)\b", "SHA-2": r"\b(?:SHA[- ]?(?:224|256|384|512)|SHA2)\b",
    "SHA-3": r"\b(?:SHA[- ]?3|SHA3|Keccak)\b", "MD5": r"\bMD5\b",
    "BLAKE2/BLAKE3": r"\bBLAKE[23](?:b|s)?\b", "HMAC": r"\bHMAC\b", "HKDF": r"\bHKDF\b",
    "PBKDF2": r"\bPBKDF2\b", "scrypt": r"\bscrypt\b", "Argon2": r"\bArgon2(?:id|i|d)?\b",
    "bcrypt": r"\bbcrypt\b", "CRC": r"\bCRC(?:-?(?:16|32|64))?\b",
}


def compile_patterns(groups):
    return {group: {name: re.compile(pattern, re.IGNORECASE) for name, pattern in values.items()}
            for group, values in groups.items()}


PATTERNS = compile_patterns({"libraries": LIBRARIES, "protocols": PROTOCOLS, "algorithms": ALGORITHMS})


def iter_files(root, include):
    for path in root.rglob("*"):
        if path.is_file() and not any(part in SKIP_DIRS and part not in include for part in path.relative_to(root).parts):
            yield path


def project_for(path, root, manifest_dirs):
    candidates = [directory for directory in manifest_dirs if directory in path.parents]
    return max(candidates, key=lambda item: len(item.parts)) if candidates else root


def add_finding(store, group, name, path, line, source, match, confidence):
    key = (group, name)
    item = store.setdefault(key, {"name": name, "evidence": [], "confidence": confidence})
    if item["confidence"] != "high" and confidence == "high":
        item["confidence"] = "high"
    evidence = {"file": str(path), "line": line, "source": source, "match": match}
    if evidence not in item["evidence"]:
        item["evidence"].append(evidence)


def scan(root, output, includes, max_file_bytes):
    files = list(iter_files(root, includes))
    manifest_dirs = {path.parent for path in files if path.name in MANIFESTS}
    projects = defaultdict(lambda: {"languages": set(), "manifests": [], "findings": {}})
    for path in files:
        relative, project = path.relative_to(root), project_for(path, root, manifest_dirs)
        record = projects[project]
        if path.name in MANIFESTS:
            record["manifests"].append(str(relative))
        if path.suffix.lower() in SOURCE_EXTENSIONS:
            record["languages"].add(path.suffix.lower().lstrip("."))
        if path.stat().st_size > max_file_bytes or (path.suffix.lower() not in SOURCE_EXTENSIONS and path.name not in MANIFESTS):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        source_type = "dependency_manifest" if path.name in MANIFESTS else "source"
        for number, line in enumerate(text.splitlines(), 1):
            for group, patterns in PATTERNS.items():
                for name, pattern in patterns.items():
                    match = pattern.search(line)
                    if match:
                        add_finding(record["findings"], group, name, relative, number, source_type, match.group(0), "high" if source_type == "dependency_manifest" else "medium")
    result = {"schema_version": "1.0", "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "repository": str(root), "scan": {"files_considered": len(files), "max_file_bytes": max_file_bytes, "skipped_directories": sorted(SKIP_DIRS)}, "projects": []}
    for project in sorted(projects, key=str):
        record = projects[project]
        crypto = {group: [record["findings"][key] for key in sorted(record["findings"]) if key[0] == group] for group in ("libraries", "protocols", "algorithms")}
        result["projects"].append({"path": "." if project == root else str(project.relative_to(root)), "languages": sorted(record["languages"]), "manifests": sorted(record["manifests"]), "crypto": crypto})
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--max-file-bytes", type=int, default=2_000_000)
    args = parser.parse_args()
    root = args.repository.resolve()
    if not root.is_dir():
        parser.error(f"repository is not a directory: {root}")
    scan(root, args.output.resolve(), set(args.include), args.max_file_bytes)


if __name__ == "__main__":
    main()
