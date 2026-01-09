package KubeSeal::Model::ObjectMeta;

use Moo;
use strict;
use warnings;
use 5.026;

use Types::Standard qw(Str Maybe HashRef);

use namespace::autoclean;

has 'name' => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

has 'namespace' => (
    is      => 'ro',
    isa     => Maybe[Str],
    default => sub { undef },
);

has 'labels' => (
    is      => 'ro',
    isa     => Maybe[HashRef[Str]],
    default => sub { undef },
);

has 'annotations' => (
    is      => 'ro',
    isa     => Maybe[HashRef[Str]],
    default => sub { undef },
);

sub to_hash {
    my ($self) = @_;

    my %hash = (
        name => $self->name,
    );

    $hash{namespace}   = $self->namespace   if defined $self->namespace;
    $hash{labels}      = $self->labels      if defined $self->labels && %{$self->labels};
    $hash{annotations} = $self->annotations if defined $self->annotations && %{$self->annotations};

    return \%hash;
}

sub from_hash {
    my ($class, $hash) = @_;

    return $class->new(
        name        => $hash->{name},
        namespace   => $hash->{namespace},
        labels      => $hash->{labels},
        annotations => $hash->{annotations},
    );
}

1;

__END__

=head1 NAME

KubeSeal::Model::ObjectMeta - Kubernetes ObjectMeta model

=head1 SYNOPSIS

    use KubeSeal::Model::ObjectMeta;

    my $meta = KubeSeal::Model::ObjectMeta->new(
        name        => 'my-secret',
        namespace   => 'default',
        labels      => { app => 'myapp' },
        annotations => { 'custom/key' => 'value' },
    );

    my $hash = $meta->to_hash;

=head1 ATTRIBUTES

=over 4

=item * B<name> - Resource name (required)

=item * B<namespace> - Kubernetes namespace (optional)

=item * B<labels> - Key-value labels (optional)

=item * B<annotations> - Key-value annotations (optional)

=back

=cut
