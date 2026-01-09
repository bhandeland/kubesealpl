package KubeSeal;

use strict;
use warnings;
use 5.026;

our $VERSION = '0.01';

use KubeSeal::Sealer;
use KubeSeal::Unsealer;
use KubeSeal::Scope qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE);
use KubeSeal::Model::Secret;
use KubeSeal::Model::SealedSecret;
use KubeSeal::Exception::Base;
use KubeSeal::Exception::CryptoError;
use KubeSeal::Exception::CertificateError;
use KubeSeal::Exception::KeyError;
use KubeSeal::Exception::ValidationError;

use Exporter 'import';

our @EXPORT_OK = qw(
    Sealer
    Unsealer
    STRICT
    NAMESPACE_WIDE
    CLUSTER_WIDE
);

our %EXPORT_TAGS = (
    all    => \@EXPORT_OK,
    scopes => [qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE)],
);

sub Sealer { 'KubeSeal::Sealer' }
sub Unsealer { 'KubeSeal::Unsealer' }

1;

__END__

=encoding utf-8

=head1 NAME

KubeSeal - Perl implementation of Bitnami Sealed Secrets encryption

=head1 SYNOPSIS

    use KubeSeal;
    use KubeSeal::Sealer;
    use KubeSeal::Unsealer;
    use KubeSeal::Scope qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE);

    # Seal a secret using a certificate
    my $sealer = KubeSeal::Sealer->from_certificate_file('/path/to/cert.pem');

    my $sealed = $sealer->seal(
        name      => 'my-secret',
        namespace => 'default',
        data      => { password => 'secret123' },
        scope     => STRICT,
    );

    print $sealed->to_yaml;

    # Unseal a secret using a private key
    my $unsealer = KubeSeal::Unsealer->from_private_key_file('/path/to/key.pem');

    my $secret = $unsealer->unseal($sealed);
    print $secret->get_data('password');

=head1 DESCRIPTION

KubeSeal is a Perl library that implements the Bitnami Sealed Secrets encryption
scheme, compatible with the kubeseal CLI tool and sealed-secrets-controller.

This allows you to:

=over 4

=item * Encrypt (seal) Kubernetes secrets without the kubeseal CLI

=item * Decrypt (unseal) sealed secrets for testing/offline operations

=item * Load certificates from files, URLs, or Kubernetes clusters

=item * Support multiple sealing scopes (strict, namespace-wide, cluster-wide)

=item * Handle key rotation with multi-key decryption

=back

=head1 SEALING SCOPES

=over 4

=item * B<STRICT> - Secret is bound to both namespace and name (default)

=item * B<NAMESPACE_WIDE> - Secret can be used with any name in the namespace

=item * B<CLUSTER_WIDE> - Secret can be used anywhere in the cluster

=back

=head1 SEE ALSO

=over 4

=item * L<https://github.com/bitnami-labs/sealed-secrets>

=item * L<KubeSeal::Sealer>

=item * L<KubeSeal::Unsealer>

=back

=head1 AUTHOR

Brandon Handeland

=head1 LICENSE

MIT License

=cut
#