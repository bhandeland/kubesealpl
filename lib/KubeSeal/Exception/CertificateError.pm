package KubeSeal::Exception::CertificateError;

use Moo;
use namespace::autoclean;

extends 'KubeSeal::Exception::Base';

has 'certificate_path' => (
    is => 'ro',
);

sub as_string {
    my ($self) = @_;
    my $msg = "Certificate error: " . $self->message;
    $msg .= " (path: " . $self->certificate_path . ")" if $self->certificate_path;
    return $msg;
}

# Subclasses
package KubeSeal::Exception::CertificateLoadError;
use Moo;
extends 'KubeSeal::Exception::CertificateError';

package KubeSeal::Exception::CertificateExpiredError;
use Moo;
extends 'KubeSeal::Exception::CertificateError';

has 'not_after' => (
    is => 'ro',
);

sub as_string {
    my ($self) = @_;
    my $msg = "Certificate expired";
    $msg .= " on " . $self->not_after if $self->not_after;
    $msg .= ": " . $self->message;
    return $msg;
}

package KubeSeal::Exception::CertificateNotYetValidError;
use Moo;
extends 'KubeSeal::Exception::CertificateError';

has 'not_before' => (
    is => 'ro',
);

sub as_string {
    my ($self) = @_;
    my $msg = "Certificate not yet valid";
    $msg .= " until " . $self->not_before if $self->not_before;
    $msg .= ": " . $self->message;
    return $msg;
}

1;

__END__

=head1 NAME

KubeSeal::Exception::CertificateError - Certificate-related exceptions

=head1 SYNOPSIS

    use Try::Tiny;
    use KubeSeal::Exception::CertificateError;

    try {
        # load certificate
    }
    catch {
        if ($_->isa('KubeSeal::Exception::CertificateExpiredError')) {
            warn "Certificate has expired: $_";
        }
    };

=head1 EXCEPTION CLASSES

=over 4

=item * B<KubeSeal::Exception::CertificateError> - Base certificate exception

=item * B<KubeSeal::Exception::CertificateLoadError> - Failed to load certificate

=item * B<KubeSeal::Exception::CertificateExpiredError> - Certificate has expired

=item * B<KubeSeal::Exception::CertificateNotYetValidError> - Certificate not yet valid

=back

=cut
