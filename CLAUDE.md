# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KubeSeal is a Perl cryptography library implementing Bitnami's Sealed Secrets encryption scheme for Kubernetes. It enables sealing (encryption) and unsealing (decryption) of Kubernetes secrets without requiring the kubeseal CLI, producing output compatible with sealed-secrets-controller.

## Common Commands

```bash
# Install dependencies
cpanm --installdeps .

# Run all tests
dzil test

# Run a single test file
prove -lv t/02-crypto.t

# Build distribution
dzil build

# Install from source
dzil install
```

## Architecture

### Core Components

- **KubeSeal::Sealer** - Public API for encrypting secrets. Factory methods: `from_certificate_file()`, `from_certificate_url()`, `from_certificate_pem()`, `from_cluster()`
- **KubeSeal::Unsealer** - Public API for decrypting secrets. Supports key rotation via multiple private keys
- **KubeSeal::Crypto** - Hybrid encryption layer: RSA-OAEP (SHA-256) encrypts a session key, AES-256-GCM encrypts data
- **KubeSeal::Certificate** - Loads X509 certificates from files, URLs, PEM strings, or Kubernetes clusters
- **KubeSeal::PrivateKey** - Manages RSA private keys for unsealing
- **KubeSeal::Scope** - Three sealing scopes: STRICT (namespace/name bound), NAMESPACE_WIDE, CLUSTER_WIDE

### Models (lib/KubeSeal/Model/)

- **Secret** - Kubernetes Secret representation
- **SealedSecret** - Bitnami SealedSecret CRD (v1alpha1)
- **ObjectMeta** - Kubernetes metadata (name, namespace, labels, annotations)

### Exception Hierarchy (lib/KubeSeal/Exception/)

Custom exceptions using Throwable: `CryptoError`, `CertificateError`, `KeyError`, `ValidationError`

### Encryption Format

```
[2 bytes BE length][RSA-OAEP encrypted session key][AES-256-GCM ciphertext + 16-byte tag]
```

- AES key: 32 bytes, Nonce: 12 zero bytes
- RSA hash and MGF1: SHA-256

## Key Dependencies

- **Moo** (2.005+) - OOP framework
- **Type::Tiny** (2.000+) - Type constraints (see lib/KubeSeal/Types.pm)
- **CryptX** (0.080+) - RSA, AES-GCM operations
- **Crypt::OpenSSL::X509** (1.915+) - Certificate parsing

## Code Conventions

- Perl 5.026+ required
- Type-driven design with extensive Type::Tiny validation
- POD documentation embedded in each module
