package KubeSeal::Model::SealedSecret;

use Moo;
use strict;
use warnings;
use 5.026;

use Types::Standard qw(Str Maybe HashRef InstanceOf);
use MIME::Base64 qw(encode_base64 decode_base64);
use YAML::XS;

use KubeSeal::Model::ObjectMeta;
use KubeSeal::Exception::ValidationError;

use namespace::autoclean;

use constant API_VERSION => 'bitnami.com/v1alpha1';
use constant KIND        => 'SealedSecret';

has 'metadata' => (
    is       => 'ro',
    isa      => InstanceOf['KubeSeal::Model::ObjectMeta'],
    required => 1,
);

has 'encrypted_data' => (
    is       => 'ro',
    isa      => HashRef[Str],  # base64-encoded encrypted values
    required => 1,
);

has 'template' => (
    is      => 'ro',
    isa     => Maybe[HashRef],
    default => sub { undef },
);

# Factory methods
sub new_sealed {
    my ($class, %args) = @_;

    my $name           = $args{name} or die "name is required";
    my $namespace      = $args{namespace} or die "namespace is required";
    my $encrypted_data = $args{encrypted_data} or die "encrypted_data is required";
    my $secret_type    = $args{type} // 'Opaque';
    my $labels         = $args{labels};
    my $annotations    = $args{annotations};

    my $template = {
        type => $secret_type,
    };

    if ($labels || $annotations) {
        $template->{metadata} = {};
        $template->{metadata}{labels}      = $labels      if $labels;
        $template->{metadata}{annotations} = $annotations if $annotations;
    }

    return $class->new(
        metadata => KubeSeal::Model::ObjectMeta->new(
            name        => $name,
            namespace   => $namespace,
            annotations => $annotations,
        ),
        encrypted_data => $encrypted_data,
        template       => $template,
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
    my $spec = $hash->{spec} or die "spec is required";

    # Handle both encryptedData and encrypted_data
    my $encrypted_data = $spec->{encryptedData} // $spec->{encrypted_data};
    unless ($encrypted_data) {
        KubeSeal::Exception::InvalidSealedSecretError->throw(
            message => "spec.encryptedData is required",
        );
    }

    return $class->new(
        metadata       => KubeSeal::Model::ObjectMeta->from_hash($metadata_hash),
        encrypted_data => $encrypted_data,
        template       => $spec->{template},
    );
}

# Instance methods
sub get_encrypted_data {
    my ($self) = @_;

    my %result;
    for my $key (keys %{$self->encrypted_data}) {
        $result{$key} = decode_base64($self->encrypted_data->{$key});
    }

    return \%result;
}

sub get_encrypted_value {
    my ($self, $key) = @_;

    return undef unless exists $self->encrypted_data->{$key};
    return decode_base64($self->encrypted_data->{$key});
}

sub to_hash {
    my ($self) = @_;

    my %spec = (
        encryptedData => $self->encrypted_data,
    );

    if (defined $self->template) {
        $spec{template} = $self->template;
    }

    my %hash = (
        apiVersion => API_VERSION,
        kind       => KIND,
        metadata   => $self->metadata->to_hash,
        spec       => \%spec,
    );

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

sub annotations {
    my ($self) = @_;
    return $self->metadata->annotations;
}

sub secret_type {
    my ($self) = @_;
    return $self->template->{type} // 'Opaque' if $self->template;
    return 'Opaque';
}

1;

__END__

=head1 NAME

KubeSeal::Model::SealedSecret - Bitnami SealedSecret resource model

=head1 SYNOPSIS

    use KubeSeal::Model::SealedSecret;

    # Create a new sealed secret
    my $sealed = KubeSeal::Model::SealedSecret->new_sealed(
        name           => 'my-secret',
        namespace      => 'default',
        encrypted_data => { password => $encrypted_base64 },
        type           => 'Opaque',
    );

    # Parse from YAML
    my $sealed = KubeSeal::Model::SealedSecret->from_yaml($yaml_content);

    # Serialize to YAML
    print $sealed->to_yaml;

    # Get encrypted data (base64 decoded)
    my $data = $sealed->get_encrypted_data;

=head1 DESCRIPTION

Model class representing a Bitnami SealedSecret CRD resource.

=head1 ATTRIBUTES

=over 4

=item * B<metadata> - ObjectMeta with name, namespace, annotations

=item * B<encrypted_data> - Hashref of base64-encoded encrypted values

=item * B<template> - Optional template spec for generated Secret

=back

=head1 METHODS

=head2 new_sealed

Create a new SealedSecret with specified parameters.

=head2 from_yaml

Parse a SealedSecret from YAML content.

=head2 from_hash

Create from a hashref structure.

=head2 to_yaml

Serialize to YAML string.

=head2 to_hash

Convert to hashref structure.

=head2 get_encrypted_data

Get all encrypted values (base64 decoded).

=head2 get_encrypted_value

Get a single encrypted value by key (base64 decoded).

=cut
