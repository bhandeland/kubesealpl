package KubeSeal::Sealer;

use Moo;
use strict;
use warnings;
use 5.026;

use Types::Standard qw(InstanceOf);
use MIME::Base64 qw(encode_base64);
use Encode qw(encode);

use KubeSeal::Certificate;
use KubeSeal::Crypto qw(encrypt);
use KubeSeal::Scope qw(
    STRICT NAMESPACE_WIDE CLUSTER_WIDE
    build_label annotation_for_scope
);
use KubeSeal::Model::ObjectMeta;
use KubeSeal::Model::Secret;
use KubeSeal::Model::SealedSecret;
use KubeSeal::Exception::ValidationError;

use namespace::autoclean;

has 'certificate' => (
    is       => 'ro',
    isa      => InstanceOf['KubeSeal::Certificate'],
    required => 1,
);

has 'public_key' => (
    is      => 'lazy',
    builder => '_build_public_key',
);

sub _build_public_key {
    my ($self) = @_;
    return $self->certificate->public_key;
}

# Factory methods
sub from_certificate_file {
    my ($class, $path, %opts) = @_;

    my $validate = $opts{validate} // 1;

    my $cert = KubeSeal::Certificate->from_file($path, validate => $validate);

    return $class->new(certificate => $cert);
}

sub from_certificate_url {
    my ($class, $url, %opts) = @_;

    my $validate   = $opts{validate} // 1;
    my $timeout    = $opts{timeout} // 30;
    my $verify_ssl = $opts{verify_ssl} // 1;

    my $cert = KubeSeal::Certificate->from_url(
        $url,
        validate   => $validate,
        timeout    => $timeout,
        verify_ssl => $verify_ssl,
    );

    return $class->new(certificate => $cert);
}

sub from_certificate_pem {
    my ($class, $pem_data, %opts) = @_;

    my $validate = $opts{validate} // 1;

    my $cert = KubeSeal::Certificate->from_string($pem_data, validate => $validate);

    return $class->new(certificate => $cert);
}

sub from_cluster {
    my ($class, %opts) = @_;

    my $cert = KubeSeal::Certificate->from_cluster(%opts);

    return $class->new(certificate => $cert);
}

# Instance methods
sub seal_value {
    my ($self, %args) = @_;

    my $value     = $args{value};
    my $namespace = $args{namespace};
    my $name      = $args{name};
    my $scope     = $args{scope} // STRICT;

    unless (defined $value) {
        KubeSeal::Exception::ValidationError->throw(
            message => 'value is required',
            field   => 'value',
        );
    }

    # Ensure value is bytes
    $value = encode('UTF-8', $value) if utf8::is_utf8($value);

    my $label = build_label(
        scope     => $scope,
        namespace => $namespace,
        name      => $name,
    );

    return encrypt(
        plaintext  => $value,
        public_key => $self->public_key,
        label      => $label,
    );
}

sub seal {
    my ($self, %args) = @_;

    my $name        = $args{name} or die "name is required";
    my $namespace   = $args{namespace} or die "namespace is required";
    my $data        = $args{data} // {};
    my $scope       = $args{scope} // STRICT;
    my $secret_type = $args{type} // 'Opaque';
    my $labels      = $args{labels};
    my $annotations = $args{annotations};

    # Build scope-specific label
    my $label = build_label(
        scope     => $scope,
        namespace => $namespace,
        name      => $name,
    );

    # Encrypt each value
    my %encrypted_data;
    for my $key (keys %$data) {
        my $value = $data->{$key};
        # Ensure value is bytes
        $value = encode('UTF-8', $value) if !ref($value) && utf8::is_utf8($value);

        my $encrypted = encrypt(
            plaintext  => $value,
            public_key => $self->public_key,
            label      => $label,
        );

        $encrypted_data{$key} = encode_base64($encrypted, '');
    }

    # Build annotations with scope
    my %result_annotations;
    %result_annotations = %$annotations if $annotations;

    my @scope_annotation = annotation_for_scope($scope);
    if (@scope_annotation) {
        $result_annotations{$scope_annotation[0]} = $scope_annotation[1];
    }

    # Create sealed secret
    return KubeSeal::Model::SealedSecret->new_sealed(
        name           => $name,
        namespace      => $namespace,
        encrypted_data => \%encrypted_data,
        type           => $secret_type,
        labels         => $labels,
        annotations    => %result_annotations ? \%result_annotations : undef,
    );
}

sub seal_secret {
    my ($self, $secret, %args) = @_;

    my $scope = $args{scope} // STRICT;

    unless ($secret->namespace) {
        KubeSeal::Exception::ValidationError->throw(
            message => 'Secret must have a namespace',
            field   => 'namespace',
        );
    }

    my $data = $secret->get_data_decoded;

    return $self->seal(
        name        => $secret->name,
        namespace   => $secret->namespace,
        data        => $data,
        scope       => $scope,
        type        => $secret->type,
        labels      => $secret->labels,
        annotations => $secret->annotations,
    );
}

1;

__END__

=head1 NAME

KubeSeal::Sealer - Seal Kubernetes secrets

=head1 SYNOPSIS

    use KubeSeal::Sealer;
    use KubeSeal::Scope qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE);

    # Create sealer from certificate file
    my $sealer = KubeSeal::Sealer->from_certificate_file('/path/to/cert.pem');

    # Or from URL
    my $sealer = KubeSeal::Sealer->from_certificate_url(
        'https://sealed-secrets-controller/v1/cert.pem'
    );

    # Seal a single value
    my $encrypted = $sealer->seal_value(
        value     => 'supersecret',
        namespace => 'default',
        name      => 'my-secret',
        scope     => STRICT,
    );

    # Seal a complete secret
    my $sealed = $sealer->seal(
        name      => 'my-secret',
        namespace => 'default',
        data      => {
            password => 'supersecret',
            apikey   => 'key123',
        },
        scope => STRICT,
        type  => 'Opaque',
    );

    # Output as YAML
    print $sealed->to_yaml;

=head1 DESCRIPTION

The Sealer class provides the primary API for encrypting Kubernetes secrets
using kubeseal-compatible encryption.

=head1 METHODS

=head2 from_certificate_file

    my $sealer = KubeSeal::Sealer->from_certificate_file($path,
        validate => 1,  # optional, default true
    );

Create a Sealer from a PEM certificate file.

=head2 from_certificate_url

    my $sealer = KubeSeal::Sealer->from_certificate_url($url,
        validate   => 1,
        timeout    => 30,
        verify_ssl => 1,
    );

Create a Sealer by fetching a certificate from a URL.

=head2 from_certificate_pem

    my $sealer = KubeSeal::Sealer->from_certificate_pem($pem_data);

Create a Sealer from PEM certificate data.

=head2 from_cluster

    my $sealer = KubeSeal::Sealer->from_cluster(
        controller_name      => 'sealed-secrets-controller',
        controller_namespace => 'kube-system',
    );

Fetch certificate from Kubernetes cluster (requires kubectl proxy).

=head2 seal_value

    my $encrypted = $sealer->seal_value(
        value     => $plaintext,
        namespace => $namespace,
        name      => $secret_name,
        scope     => STRICT,
    );

Encrypt a single value. Returns raw encrypted bytes.

=head2 seal

    my $sealed = $sealer->seal(
        name        => $name,
        namespace   => $namespace,
        data        => \%data,
        scope       => STRICT,
        type        => 'Opaque',
        labels      => \%labels,
        annotations => \%annotations,
    );

Seal a complete secret. Returns a KubeSeal::Model::SealedSecret object.

=head2 seal_secret

    my $sealed = $sealer->seal_secret($secret, scope => STRICT);

Seal an existing KubeSeal::Model::Secret object.

=cut
