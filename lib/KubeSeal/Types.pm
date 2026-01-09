package KubeSeal::Types;

use strict;
use warnings;
use 5.026;

use Type::Library -base, -declare => qw(
    SealingScope
    RSAPublicKey
    RSAPrivateKey
    X509Certificate
    SecretData
    EncryptedData
    KubernetesName
    KubernetesNamespace
);

use Type::Utils -all;
use Types::Standard qw(Str HashRef Enum InstanceOf);
use namespace::autoclean;

declare SealingScope,
    as Enum[qw(strict namespace-wide cluster-wide)];

declare RSAPublicKey,
    as InstanceOf['Crypt::PK::RSA'],
    where { $_->is_private == 0 || $_->is_private == 1 },  # Can be either, but must be valid
    message { "Value must be a Crypt::PK::RSA object" };

declare RSAPrivateKey,
    as InstanceOf['Crypt::PK::RSA'],
    where { $_->is_private },
    message { "Value must be a Crypt::PK::RSA private key" };

declare X509Certificate,
    as InstanceOf['Crypt::OpenSSL::X509'],
    message { "Value must be a Crypt::OpenSSL::X509 object" };

declare SecretData,
    as HashRef[Str],
    message { "Secret data must be a hashref of string values" };

declare EncryptedData,
    as HashRef[Str],
    message { "Encrypted data must be a hashref of base64-encoded strings" };

# Kubernetes naming constraints
# Names must be lowercase alphanumeric with dashes, max 253 chars
declare KubernetesName,
    as Str,
    where { /^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$/ && length($_) <= 253 },
    message { "Invalid Kubernetes name: must be lowercase alphanumeric with dashes, max 253 chars" };

declare KubernetesNamespace,
    as Str,
    where { /^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$/ && length($_) <= 63 },
    message { "Invalid Kubernetes namespace: must be lowercase alphanumeric with dashes, max 63 chars" };

1;

__END__

=head1 NAME

KubeSeal::Types - Type constraints for KubeSeal

=head1 SYNOPSIS

    use KubeSeal::Types qw(SealingScope RSAPublicKey);

    has 'scope' => (
        is  => 'ro',
        isa => SealingScope,
    );

=head1 TYPES

=over 4

=item * B<SealingScope> - One of: strict, namespace-wide, cluster-wide

=item * B<RSAPublicKey> - A Crypt::PK::RSA public key object

=item * B<RSAPrivateKey> - A Crypt::PK::RSA private key object

=item * B<X509Certificate> - A Crypt::OpenSSL::X509 certificate object

=item * B<SecretData> - HashRef of string values

=item * B<EncryptedData> - HashRef of base64-encoded strings

=item * B<KubernetesName> - Valid Kubernetes resource name

=item * B<KubernetesNamespace> - Valid Kubernetes namespace name

=back

=cut
