package KubeSeal::PrivateKey;

use Moo;
use strict;
use warnings;
use 5.026;

use Crypt::PK::RSA;
use Path::Tiny qw(path);

use KubeSeal::Exception::KeyError;

use namespace::autoclean;

has 'pem_data' => (
    is       => 'ro',
    required => 1,
);

has 'password' => (
    is      => 'ro',
    default => sub { undef },
);

has 'private_key' => (
    is      => 'lazy',
    builder => '_build_private_key',
);

sub _build_private_key {
    my ($self) = @_;

    my $pem      = $self->pem_data;
    my $password = $self->password;

    my $key;
    eval {
        if (defined $password) {
            $key = Crypt::PK::RSA->new(\$pem, $password);
        }
        else {
            $key = Crypt::PK::RSA->new(\$pem);
        }
    };
    if ($@) {
        if ($@ =~ /password|decrypt/i) {
            KubeSeal::Exception::KeyDecryptError->throw(
                message => "Failed to decrypt private key: $@",
            );
        }
        KubeSeal::Exception::KeyLoadError->throw(
            message => "Failed to load private key: $@",
        );
    }

    # Verify it's actually a private key
    unless ($key->is_private) {
        KubeSeal::Exception::InvalidKeyError->throw(
            message       => "The key is not a private key",
            expected_type => 'private',
        );
    }

    return $key;
}

# Factory methods
sub from_file {
    my ($class, $filepath, %opts) = @_;

    my $password = $opts{password};
    my $file = path($filepath);

    unless ($file->exists) {
        KubeSeal::Exception::KeyLoadError->throw(
            message  => "Private key file not found: $filepath",
            key_path => $filepath,
        );
    }

    my $pem_data;
    eval {
        $pem_data = $file->slurp_raw;
    };
    if ($@) {
        KubeSeal::Exception::KeyLoadError->throw(
            message  => "Failed to read private key file: $@",
            key_path => $filepath,
        );
    }

    return $class->new(
        pem_data => $pem_data,
        password => $password,
    );
}

sub from_string {
    my ($class, $pem_string, %opts) = @_;

    my $password = $opts{password};

    return $class->new(
        pem_data => $pem_string,
        password => $password,
    );
}

sub from_directory {
    my ($class, $directory, %opts) = @_;

    my $password = $opts{password};
    my $pattern  = $opts{pattern} // '*.pem';

    my $dir = path($directory);

    unless ($dir->is_dir) {
        KubeSeal::Exception::KeyLoadError->throw(
            message  => "Directory not found: $directory",
            key_path => $directory,
        );
    }

    my @keys;

    for my $file ($dir->children(qr/\.pem$/)) {
        eval {
            my $key = $class->from_file($file->stringify, password => $password);
            push @keys, $key;
        };
        # Skip files that aren't valid private keys
    }

    return \@keys;
}

# Convenience method to get raw key
sub key {
    my ($self) = @_;
    return $self->private_key;
}

# Key size in bits
sub key_size {
    my ($self) = @_;
    return $self->private_key->size * 8;
}

# Check if key is encrypted
sub is_encrypted {
    my ($class, $pem_data) = @_;

    # Check for encrypted PEM markers
    return $pem_data =~ /ENCRYPTED/;
}

1;

__END__

=head1 NAME

KubeSeal::PrivateKey - RSA private key loading

=head1 SYNOPSIS

    use KubeSeal::PrivateKey;

    # Load from file
    my $key = KubeSeal::PrivateKey->from_file('/path/to/key.pem');

    # Load from file with password
    my $key = KubeSeal::PrivateKey->from_file('/path/to/key.pem',
        password => 'secret',
    );

    # Load from string
    my $key = KubeSeal::PrivateKey->from_string($pem_data);

    # Load all keys from directory
    my $keys = KubeSeal::PrivateKey->from_directory('/path/to/keys/',
        pattern => '*.pem',
    );

    # Access the Crypt::PK::RSA object
    my $rsa_key = $key->private_key;

=head1 DESCRIPTION

Loads RSA private keys for use with sealed secrets decryption.
Supports password-protected keys and loading from directories.

=head1 METHODS

=head2 from_file

    my $key = KubeSeal::PrivateKey->from_file($path,
        password => $password,  # optional
    );

Load private key from a PEM file.

=head2 from_string

    my $key = KubeSeal::PrivateKey->from_string($pem_data,
        password => $password,  # optional
    );

Parse private key from a PEM string.

=head2 from_directory

    my $keys = KubeSeal::PrivateKey->from_directory($dir,
        password => $password,  # optional
        pattern  => '*.pem',    # optional
    );

Load all private keys from a directory. Returns arrayref of PrivateKey objects.

=head2 private_key

    my $rsa = $key->private_key;

Returns the Crypt::PK::RSA private key object.

=head2 key

    my $rsa = $key->key;

Alias for private_key.

=head2 key_size

    my $bits = $key->key_size;

Returns key size in bits (e.g., 2048, 4096).

=cut
