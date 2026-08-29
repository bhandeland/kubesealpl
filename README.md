# KubeSeal

> **This repo is mirrored from [GitLab](https://gitlab.com/nighthawk-oss/kubesealpl).** Issues, merge requests, and contributions should go there.

Perl implementation of Bitnami Sealed Secrets encryption, compatible with the kubeseal CLI tool and sealed-secrets-controller.

## Synopsis

```perl
use KubeSeal::Sealer;
use KubeSeal::Unsealer;
use KubeSeal::Scope qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE);

# Seal secrets using a certificate
my $sealer = KubeSeal::Sealer->from_certificate_file('/path/to/cert.pem');

my $sealed = $sealer->seal(
    name      => 'my-secret',
    namespace => 'default',
    data      => {
        password => 'supersecret',
        api_key  => 'key123',
    },
    scope => STRICT,
);

# Output as YAML for kubectl apply
print $sealed->to_yaml;

# Unseal secrets (for testing/offline operations)
my $unsealer = KubeSeal::Unsealer->from_private_key_file('/path/to/key.pem');
my $secret = $unsealer->unseal($sealed);

print $secret->get_data('password');  # 'supersecret'
```

## Description

KubeSeal allows you to:

- Encrypt (seal) Kubernetes secrets without the kubeseal CLI
- Decrypt (unseal) sealed secrets for testing/offline operations
- Load certificates from files, URLs, or Kubernetes clusters
- Support multiple sealing scopes (strict, namespace-wide, cluster-wide)
- Handle key rotation with multi-key decryption

## Installation

### From CPAN

```bash
cpanm KubeSeal
```

### From Source

```bash
git clone https://github.com/brandon/perl-kubeseal.git
cd perl-kubeseal
cpanm --installdeps .
dzil build
dzil install
```

## Sealing Scopes

KubeSeal supports three sealing scopes that determine how secrets are bound:

- **STRICT** (default) - Secret is bound to both namespace AND name. The sealed secret can only be decrypted for the exact namespace/name combination.

- **NAMESPACE_WIDE** - Secret is bound to namespace only. Can be used with any secret name within the specified namespace.

- **CLUSTER_WIDE** - No binding. The sealed secret can be decrypted anywhere in the cluster.

```perl
use KubeSeal::Scope qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE);

# Strict scope (default)
my $sealed = $sealer->seal(
    name      => 'my-secret',
    namespace => 'production',
    data      => { password => 'secret' },
    scope     => STRICT,
);

# Namespace-wide scope
my $sealed = $sealer->seal(
    name      => 'shared-secret',
    namespace => 'production',
    data      => { password => 'secret' },
    scope     => NAMESPACE_WIDE,
);

# Cluster-wide scope
my $sealed = $sealer->seal(
    name      => 'global-secret',
    namespace => 'default',
    data      => { password => 'secret' },
    scope     => CLUSTER_WIDE,
);
```

## Loading Certificates

```perl
# From a file
my $sealer = KubeSeal::Sealer->from_certificate_file('/path/to/cert.pem');

# From a URL (e.g., sealed-secrets-controller endpoint)
my $sealer = KubeSeal::Sealer->from_certificate_url(
    'https://sealed-secrets-controller.kube-system.svc/v1/cert.pem',
    verify_ssl => 1,
    timeout    => 30,
);

# From PEM string
my $sealer = KubeSeal::Sealer->from_certificate_pem($pem_data);

# From Kubernetes cluster (requires kubectl proxy)
my $sealer = KubeSeal::Sealer->from_cluster(
    controller_name      => 'sealed-secrets-controller',
    controller_namespace => 'kube-system',
);
```

## Key Rotation Support

The Unsealer supports multiple private keys for key rotation scenarios:

```perl
# Load all keys from a directory
my $unsealer = KubeSeal::Unsealer->from_private_keys_directory(
    '/path/to/keys/',
    pattern => '*.pem',
);

# The unsealer will try each key until one succeeds
my $secret = $unsealer->unseal($sealed_secret);
```

## Working with Secrets

```perl
use KubeSeal::Model::Secret;
use KubeSeal::Model::SealedSecret;

# Create a secret
my $secret = KubeSeal::Model::Secret->from_data(
    name      => 'my-secret',
    namespace => 'default',
    data      => { password => 'secret' },
    labels    => { app => 'myapp' },
);

# Seal an existing secret
my $sealed = $sealer->seal_secret($secret);

# Parse sealed secret from YAML
my $sealed = KubeSeal::Model::SealedSecret->from_yaml($yaml_content);

# Convert to YAML
print $sealed->to_yaml;
```

## Dependencies

- Moo >= 2.005
- Type::Tiny >= 2.000
- CryptX >= 0.080
- Crypt::OpenSSL::X509 >= 1.915
- YAML::XS >= 0.88
- HTTP::Tiny (core)
- IO::Socket::SSL >= 2.084

## Compatibility

This module produces output compatible with:

- Bitnami sealed-secrets-controller
- kubeseal CLI tool
- SealedSecret CRD (bitnami.com/v1alpha1)

## See Also

- [Bitnami Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
- [kubeseal CLI](https://github.com/bitnami-labs/sealed-secrets#installation)

## Author

Brandon Handeland

## License

MIT License
