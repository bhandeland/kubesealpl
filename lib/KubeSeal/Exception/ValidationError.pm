package KubeSeal::Exception::ValidationError;

use Moo;
use namespace::autoclean;

extends 'KubeSeal::Exception::Base';

has 'field' => (
    is => 'ro',
);

has 'value' => (
    is => 'ro',
);

has 'errors' => (
    is      => 'ro',
    default => sub { [] },
);

sub as_string {
    my ($self) = @_;
    my $msg = "Validation error";
    $msg .= " for field '" . $self->field . "'" if $self->field;
    $msg .= ": " . $self->message;
    if (@{$self->errors}) {
        $msg .= " (" . join(", ", @{$self->errors}) . ")";
    }
    return $msg;
}

# Subclasses
package KubeSeal::Exception::InvalidSealedSecretError;
use Moo;
extends 'KubeSeal::Exception::ValidationError';

sub as_string {
    my ($self) = @_;
    return "Invalid SealedSecret: " . $self->message;
}

package KubeSeal::Exception::InvalidSecretError;
use Moo;
extends 'KubeSeal::Exception::ValidationError';

sub as_string {
    my ($self) = @_;
    return "Invalid Secret: " . $self->message;
}

package KubeSeal::Exception::ScopeError;
use Moo;
extends 'KubeSeal::Exception::ValidationError';

has 'scope' => (
    is => 'ro',
);

has 'namespace' => (
    is => 'ro',
);

has 'name' => (
    is => 'ro',
);

sub as_string {
    my ($self) = @_;
    return sprintf(
        "Scope error for scope '%s' (namespace=%s, name=%s): %s",
        $self->scope // 'unknown',
        $self->namespace // 'none',
        $self->name // 'none',
        $self->message
    );
}

1;

__END__

=head1 NAME

KubeSeal::Exception::ValidationError - Data validation exceptions

=head1 SYNOPSIS

    use Try::Tiny;
    use KubeSeal::Exception::ValidationError;

    try {
        # validate data
    }
    catch {
        if ($_->isa('KubeSeal::Exception::InvalidSealedSecretError')) {
            warn "Invalid sealed secret: $_";
        }
    };

=head1 EXCEPTION CLASSES

=over 4

=item * B<KubeSeal::Exception::ValidationError> - Base validation exception

=item * B<KubeSeal::Exception::InvalidSealedSecretError> - Invalid SealedSecret

=item * B<KubeSeal::Exception::InvalidSecretError> - Invalid Secret

=item * B<KubeSeal::Exception::ScopeError> - Scope configuration error

=back

=cut
