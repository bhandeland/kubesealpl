package KubeSeal::Exception::Base;

use Moo;
use namespace::autoclean;

with 'Throwable';

has 'message' => (
    is       => 'ro',
    required => 1,
);

sub as_string {
    my ($self) = @_;
    return $self->message;
}

use overload
    '""'     => 'as_string',
    fallback => 1;

1;

__END__

=head1 NAME

KubeSeal::Exception::Base - Base exception class for KubeSeal

=head1 SYNOPSIS

    use Try::Tiny;
    use KubeSeal::Exception::Base;

    try {
        KubeSeal::Exception::Base->throw(message => 'Something went wrong');
    }
    catch {
        warn "Caught exception: $_";
    };

=head1 DESCRIPTION

Base class for all KubeSeal exceptions. Uses the Throwable role for
exception handling.

=head1 ATTRIBUTES

=over 4

=item * B<message> - The error message (required)

=back

=cut
