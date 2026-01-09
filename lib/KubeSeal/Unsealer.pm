package KubeSeal::Unsealer;

use Moo;
use strict;
use warnings;
use 5.026;

use Types::Standard qw(ArrayRef InstanceOf);
use MIME::Base64 qw(encode_base64 decode_base64);

use KubeSeal::PrivateKey;
use KubeSeal::Crypto qw(decrypt_with_any_key);
use KubeSeal::Scope qw(STRICT build_label scope_from_annotations);
use KubeSeal::Model::ObjectMeta;
use KubeSeal::Model::Secret;
use KubeSeal::Model::SealedSecret;
use KubeSeal::Exception::ValidationError;
use KubeSeal::Exception::KeyError;

use namespace::autoclean;

has 'private_keys' => (
    is       => 'ro',
    isa      => ArrayRef[InstanceOf['KubeSeal::PrivateKey']],
    required => 1,
);

# Build actual crypto keys lazily
has '_crypto_keys' => (
    is      => 'lazy',
    builder => '_build_crypto_keys',
);

sub _build_crypto_keys {
    my ($self) = @_;
    return [map { $_->private_key } @{$self->private_keys}];
}

sub BUILD {
    my ($self) = @_;

    unless (@{$self->private_keys}) {
        KubeSeal::Exception::InvalidKeyError->throw(
            message => 'At least one private key is required',
        );
    }
}

# Factory methods
sub from_private_key {
    my ($class, $private_key) = @_;

    # Accept either a PrivateKey object or a Crypt::PK::RSA object
    if (ref($private_key) eq 'Crypt::PK::RSA') {
        # Wrap in PrivateKey object
        $private_key = KubeSeal::PrivateKey->new(
            pem_data => $private_key->export_key_pem('private'),
        );
    }

    return $class->new(private_keys => [$private_key]);
}

sub from_private_key_file {
    my ($class, $path, %opts) = @_;

    my $password = $opts{password};

    my $key = KubeSeal::PrivateKey->from_file($path, password => $password);

    return $class->new(private_keys => [$key]);
}

sub from_private_keys_directory {
    my ($class, $directory, %opts) = @_;

    my $password = $opts{password};
    my $pattern  = $opts{pattern} // '*.pem';

    my $keys = KubeSeal::PrivateKey->from_directory(
        $directory,
        password => $password,
        pattern  => $pattern,
    );

    unless (@$keys) {
        KubeSeal::Exception::KeyLoadError->throw(
            message  => "No private keys found in directory: $directory",
            key_path => $directory,
        );
    }

    return $class->new(private_keys => $keys);
}

# Properties
sub key_count {
    my ($self) = @_;
    return scalar @{$self->private_keys};
}

# Instance methods
sub unseal_value {
    my ($self, %args) = @_;

    my $encrypted_value = $args{encrypted_value};
    my $namespace       = $args{namespace};
    my $name            = $args{name};
    my $scope           = $args{scope} // STRICT;

    unless (defined $encrypted_value) {
        KubeSeal::Exception::ValidationError->throw(
            message => 'encrypted_value is required',
            field   => 'encrypted_value',
        );
    }

    my $label = build_label(
        scope     => $scope,
        namespace => $namespace,
        name      => $name,
    );

    return decrypt_with_any_key(
        ciphertext   => $encrypted_value,
        private_keys => $self->_crypto_keys,
        label        => $label,
    );
}

sub unseal {
    my ($self, $sealed_secret, %args) = @_;

    my $scope = $args{scope};

    # Determine scope from annotations if not provided
    unless (defined $scope) {
        $scope = scope_from_annotations($sealed_secret->annotations);
    }

    my $name      = $sealed_secret->name;
    my $namespace = $sealed_secret->namespace;

    # Build label for decryption
    my $label = build_label(
        scope     => $scope,
        namespace => $namespace,
        name      => $name,
    );

    # Decrypt each value
    my %decrypted_data;
    my $encrypted_data = $sealed_secret->encrypted_data;

    for my $key (keys %$encrypted_data) {
        my $encrypted_b64 = $encrypted_data->{$key};
        my $encrypted = decode_base64($encrypted_b64);

        my $plaintext = decrypt_with_any_key(
            ciphertext   => $encrypted,
            private_keys => $self->_crypto_keys,
            label        => $label,
        );

        # Store as base64 for the Secret
        $decrypted_data{$key} = encode_base64($plaintext, '');
    }

    # Get template metadata if available
    my $template    = $sealed_secret->template;
    my $secret_type = 'Opaque';
    my $labels;
    my $annotations;

    if ($template) {
        $secret_type = $template->{type} // 'Opaque';
        if ($template->{metadata}) {
            $labels      = $template->{metadata}{labels};
            $annotations = $template->{metadata}{annotations};
        }
    }

    return KubeSeal::Model::Secret->new(
        metadata => KubeSeal::Model::ObjectMeta->new(
            name        => $name,
            namespace   => $namespace,
            labels      => $labels,
            annotations => $annotations,
        ),
        type => $secret_type,
        data => \%decrypted_data,
    );
}

1;

__END__

=head1 NAME

KubeSeal::Unsealer - Unseal Kubernetes SealedSecrets

=head1 SYNOPSIS

    use KubeSeal::Unsealer;
    use KubeSeal::Model::SealedSecret;

    # Create unsealer from private key file
    my $unsealer = KubeSeal::Unsealer->from_private_key_file('/path/to/key.pem');

    # Or with password-protected key
    my $unsealer = KubeSeal::Unsealer->from_private_key_file(
        '/path/to/key.pem',
        password => 'secret',
    );

    # Or from directory (for key rotation)
    my $unsealer = KubeSeal::Unsealer->from_private_keys_directory('/path/to/keys/');

    # Parse sealed secret from YAML
    my $sealed = KubeSeal::Model::SealedSecret->from_yaml($yaml_content);

    # Unseal it
    my $secret = $unsealer->unseal($sealed);

    # Access decrypted data
    my $password = $secret->get_data('password');

=head1 DESCRIPTION

The Unsealer class provides the primary API for decrypting Kubernetes
SealedSecrets. This is useful for testing and offline operations.

Note: In production, unsealing typically happens on the cluster side
via the sealed-secrets-controller.

=head1 METHODS

=head2 from_private_key

    my $unsealer = KubeSeal::Unsealer->from_private_key($key);

Create an Unsealer from a KubeSeal::PrivateKey object.

=head2 from_private_key_file

    my $unsealer = KubeSeal::Unsealer->from_private_key_file($path,
        password => $password,  # optional
    );

Create an Unsealer from a PEM private key file.

=head2 from_private_keys_directory

    my $unsealer = KubeSeal::Unsealer->from_private_keys_directory($dir,
        password => $password,  # optional
        pattern  => '*.pem',    # optional
    );

Create an Unsealer from all private keys in a directory.
Supports key rotation by trying each key.

=head2 key_count

    my $count = $unsealer->key_count;

Returns the number of private keys available.

=head2 unseal_value

    my $plaintext = $unsealer->unseal_value(
        encrypted_value => $encrypted_bytes,
        namespace       => $namespace,
        name            => $secret_name,
        scope           => STRICT,
    );

Decrypt a single value. Returns raw bytes.

=head2 unseal

    my $secret = $unsealer->unseal($sealed_secret,
        scope => STRICT,  # optional, auto-detected from annotations
    );

Unseal a SealedSecret to a Secret object.

=cut
