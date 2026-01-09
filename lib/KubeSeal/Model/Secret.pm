package KubeSeal::Model::Secret;

use Moo;
use strict;
use warnings;
use 5.026;

use Types::Standard qw(Str Maybe HashRef InstanceOf);
use MIME::Base64 qw(encode_base64 decode_base64);
use YAML::XS;
use Encode qw(encode decode);

use KubeSeal::Model::ObjectMeta;
use KubeSeal::Exception::ValidationError;

use namespace::autoclean;

use constant API_VERSION => 'v1';
use constant KIND        => 'Secret';

has 'metadata' => (
    is       => 'ro',
    isa      => InstanceOf['KubeSeal::Model::ObjectMeta'],
    required => 1,
);

has 'type' => (
    is      => 'ro',
    isa     => Str,
    default => sub { 'Opaque' },
);

has 'data' => (
    is      => 'ro',
    isa     => Maybe[HashRef[Str]],  # base64-encoded values
    default => sub { undef },
);

has 'string_data' => (
    is      => 'ro',
    isa     => Maybe[HashRef[Str]],  # plain text values
    default => sub { undef },
);

# Factory methods
sub from_string_data {
    my ($class, %args) = @_;

    my $name        = $args{name} or die "name is required";
    my $namespace   = $args{namespace} or die "namespace is required";
    my $data        = $args{data} // {};
    my $secret_type = $args{type} // 'Opaque';
    my $labels      = $args{labels};
    my $annotations = $args{annotations};

    return $class->new(
        metadata => KubeSeal::Model::ObjectMeta->new(
            name        => $name,
            namespace   => $namespace,
            labels      => $labels,
            annotations => $annotations,
        ),
        type        => $secret_type,
        string_data => $data,
    );
}

sub from_data {
    my ($class, %args) = @_;

    my $name        = $args{name} or die "name is required";
    my $namespace   = $args{namespace} or die "namespace is required";
    my $data        = $args{data} // {};
    my $secret_type = $args{type} // 'Opaque';
    my $labels      = $args{labels};
    my $annotations = $args{annotations};

    # Encode data values to base64
    my %encoded_data;
    for my $key (keys %$data) {
        my $value = $data->{$key};
        # Handle both string and bytes
        $value = encode('UTF-8', $value) if !ref($value) && utf8::is_utf8($value);
        $encoded_data{$key} = encode_base64($value, '');
    }

    return $class->new(
        metadata => KubeSeal::Model::ObjectMeta->new(
            name        => $name,
            namespace   => $namespace,
            labels      => $labels,
            annotations => $annotations,
        ),
        type => $secret_type,
        data => \%encoded_data,
    );
}

sub from_yaml {
    my ($class, $yaml_content) = @_;

    my $hash = YAML::XS::Load($yaml_content);

    return $class->from_hash($hash);
}

sub from_hash {
    my ($class, $hash) = @_;

    my $metadata_hash = $hash->{metadata} or die "metadata is required";

    return $class->new(
        metadata => KubeSeal::Model::ObjectMeta->from_hash($metadata_hash),
        type        => $hash->{type} // 'Opaque',
        data        => $hash->{data},
        string_data => $hash->{stringData},
    );
}

# Instance methods
sub get_data_decoded {
    my ($self) = @_;

    my %result;

    if ($self->data) {
        for my $key (keys %{$self->data}) {
            $result{$key} = decode_base64($self->data->{$key});
        }
    }

    if ($self->string_data) {
        for my $key (keys %{$self->string_data}) {
            $result{$key} = encode('UTF-8', $self->string_data->{$key});
        }
    }

    return \%result;
}

sub get_data {
    my ($self, $key) = @_;

    my $decoded = $self->get_data_decoded;
    return $decoded->{$key};
}

sub to_hash {
    my ($self) = @_;

    my %hash = (
        apiVersion => API_VERSION,
        kind       => KIND,
        metadata   => $self->metadata->to_hash,
        type       => $self->type,
    );

    $hash{data}       = $self->data       if defined $self->data && %{$self->data};
    $hash{stringData} = $self->string_data if defined $self->string_data && %{$self->string_data};

    return \%hash;
}

sub to_yaml {
    my ($self) = @_;

    local $YAML::XS::Boolean = "JSON::PP";
    return YAML::XS::Dump($self->to_hash);
}

# Convenience accessors
sub name {
    my ($self) = @_;
    return $self->metadata->name;
}

sub namespace {
    my ($self) = @_;
    return $self->metadata->namespace;
}

sub labels {
    my ($self) = @_;
    return $self->metadata->labels;
}

sub annotations {
    my ($self) = @_;
    return $self->metadata->annotations;
}

1;

__END__

=head1 NAME

KubeSeal::Model::Secret - Kubernetes Secret resource model

=head1 SYNOPSIS

    use KubeSeal::Model::Secret;

    # Create from string data
    my $secret = KubeSeal::Model::Secret->from_string_data(
        name      => 'my-secret',
        namespace => 'default',
        data      => { password => 'secret123' },
    );

    # Create from binary data
    my $secret = KubeSeal::Model::Secret->from_data(
        name      => 'my-secret',
        namespace => 'default',
        data      => { password => 'secret123' },
    );

    # Parse from YAML
    my $secret = KubeSeal::Model::Secret->from_yaml($yaml_content);

    # Serialize to YAML
    print $secret->to_yaml;

    # Get decoded data
    my $data = $secret->get_data_decoded;
    print $data->{password};

=head1 DESCRIPTION

Model class representing a Kubernetes Secret resource.

=head1 ATTRIBUTES

=over 4

=item * B<metadata> - ObjectMeta with name, namespace, labels, annotations

=item * B<type> - Secret type (default: Opaque)

=item * B<data> - Base64-encoded secret data

=item * B<string_data> - Plain text secret data (will be encoded)

=back

=cut
