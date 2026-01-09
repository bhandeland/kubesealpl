package KubeSeal::Exception::KeyError;

use Moo;
use namespace::autoclean;

extends 'KubeSeal::Exception::Base';

has 'key_path' => (
    is => 'ro',
);

sub as_string {
    my ($self) = @_;
    my $msg = "Key error: " . $self->message;
    $msg .= " (path: " . $self->key_path . ")" if $self->key_path;
    return $msg;
}

# Subclasses
package KubeSeal::Exception::KeyLoadError;
use Moo;
extends 'KubeSeal::Exception::KeyError';

package KubeSeal::Exception::KeyDecryptError;
use Moo;
extends 'KubeSeal::Exception::KeyError';

sub as_string {
    my ($self) = @_;
    return "Failed to decrypt private key: " . $self->message;
}

package KubeSeal::Exception::InvalidKeyError;
use Moo;
extends 'KubeSeal::Exception::KeyError';

has 'expected_type' => (
    is => 'ro',
);

sub as_string {
    my ($self) = @_;
    my $msg = "Invalid key";
    $msg .= " (expected " . $self->expected_type . ")" if $self->expected_type;
    $msg .= ": " . $self->message;
    return $msg;
}

1;

__END__

=head1 NAME

KubeSeal::Exception::KeyError - Private key-related exceptions

=head1 SYNOPSIS

    use Try::Tiny;
    use KubeSeal::Exception::KeyError;

    try {
        # load private key
    }
    catch {
        if ($_->isa('KubeSeal::Exception::KeyLoadError')) {
            warn "Failed to load key: $_";
        }
    };

=head1 EXCEPTION CLASSES

=over 4

=item * B<KubeSeal::Exception::KeyError> - Base key exception

=item * B<KubeSeal::Exception::KeyLoadError> - Failed to load key

=item * B<KubeSeal::Exception::KeyDecryptError> - Failed to decrypt key

=item * B<KubeSeal::Exception::InvalidKeyError> - Key type mismatch

=back

=cut
