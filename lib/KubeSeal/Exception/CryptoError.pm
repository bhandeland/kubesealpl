package KubeSeal::Exception::CryptoError;

use Moo;
use namespace::autoclean;

extends 'KubeSeal::Exception::Base';

has 'operation' => (
    is      => 'ro',
    default => sub { 'unknown' },
);

sub as_string {
    my ($self) = @_;
    return sprintf("Crypto error during %s: %s", $self->operation, $self->message);
}

# Subclasses for specific crypto errors
package KubeSeal::Exception::EncryptionError;
use Moo;
extends 'KubeSeal::Exception::CryptoError';
has '+operation' => (default => sub { 'encryption' });

package KubeSeal::Exception::DecryptionError;
use Moo;
extends 'KubeSeal::Exception::CryptoError';
has '+operation' => (default => sub { 'decryption' });

package KubeSeal::Exception::NoMatchingKeyError;
use Moo;
extends 'KubeSeal::Exception::DecryptionError';

has 'keys_tried' => (
    is      => 'ro',
    default => sub { 0 },
);

sub as_string {
    my ($self) = @_;
    return sprintf(
        "No matching key found for decryption (tried %d keys): %s",
        $self->keys_tried,
        $self->message
    );
}

1;

__END__

=head1 NAME

KubeSeal::Exception::CryptoError - Cryptographic operation exceptions

=head1 SYNOPSIS

    use Try::Tiny;
    use KubeSeal::Exception::CryptoError;

    try {
        # encryption code
    }
    catch {
        if ($_->isa('KubeSeal::Exception::EncryptionError')) {
            warn "Encryption failed: $_";
        }
    };

=head1 DESCRIPTION

Exception classes for cryptographic operations.

=head1 EXCEPTION CLASSES

=over 4

=item * B<KubeSeal::Exception::CryptoError> - Base crypto exception

=item * B<KubeSeal::Exception::EncryptionError> - Encryption failed

=item * B<KubeSeal::Exception::DecryptionError> - Decryption failed

=item * B<KubeSeal::Exception::NoMatchingKeyError> - No private key matched

=back

=cut
