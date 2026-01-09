package KubeSeal::Crypto;

use strict;
use warnings;
use 5.026;

use Crypt::PK::RSA;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG qw(random_bytes);
use MIME::Base64 qw(encode_base64 decode_base64);

use KubeSeal::Exception::CryptoError;

use Exporter 'import';

our @EXPORT_OK = qw(
    encrypt
    decrypt
    decrypt_with_any_key
    AES_KEY_SIZE
    AES_NONCE
);

# Constants matching kubeseal
use constant AES_KEY_SIZE => 32;         # 256 bits
use constant AES_NONCE    => "\x00" x 12;  # 96-bit zero nonce

sub encrypt {
    my (%args) = @_;

    my $plaintext  = $args{plaintext};
    my $public_key = $args{public_key};
    my $label      = $args{label} // '';

    # Validate inputs
    unless (defined $plaintext) {
        KubeSeal::Exception::EncryptionError->throw(
            message => 'plaintext is required',
        );
    }

    unless (defined $public_key && ref($public_key) && $public_key->isa('Crypt::PK::RSA')) {
        KubeSeal::Exception::EncryptionError->throw(
            message => 'public_key must be a Crypt::PK::RSA object',
        );
    }

    my $result;
    my $error;

    {
        local $@;
        eval {
            # Generate random 32-byte session key
            my $session_key = random_bytes(AES_KEY_SIZE);

            # Encrypt session key with RSA-OAEP (SHA-256 hash, SHA-256 MGF1)
            my $encrypted_key = $public_key->encrypt(
                $session_key,
                'oaep',
                'SHA256',
                $label,
            );

            # Encrypt plaintext with AES-256-GCM
            my ($ciphertext, $tag) = gcm_encrypt_authenticate(
                'AES',
                $session_key,
                AES_NONCE,
                undef,
                $plaintext,
            );

            # Append tag to ciphertext
            my $aes_output = $ciphertext . $tag;

            # Build output: [2-byte big-endian length] | [encrypted key] | [ciphertext+tag]
            my $length_bytes = pack('n', length($encrypted_key));

            $result = $length_bytes . $encrypted_key . $aes_output;
        };
        $error = $@;
    }

    if ($error) {
        KubeSeal::Exception::EncryptionError->throw(
            message => "Encryption failed: $error",
        );
    }

    return $result;
}

sub decrypt {
    my (%args) = @_;

    my $ciphertext  = $args{ciphertext};
    my $private_key = $args{private_key};
    my $label       = $args{label} // '';

    # Validate inputs
    unless (defined $ciphertext) {
        KubeSeal::Exception::DecryptionError->throw(
            message => 'ciphertext is required',
        );
    }

    unless (defined $private_key && ref($private_key) && $private_key->isa('Crypt::PK::RSA')) {
        KubeSeal::Exception::DecryptionError->throw(
            message => 'private_key must be a Crypt::PK::RSA object',
        );
    }

    if (length($ciphertext) < 2) {
        KubeSeal::Exception::DecryptionError->throw(
            message => 'Ciphertext too short: missing length header',
        );
    }

    my $result;
    my $error;

    {
        local $@;
        eval {
            # Extract encrypted key length (2 bytes, big-endian)
            my $key_length = unpack('n', substr($ciphertext, 0, 2));

            if (length($ciphertext) < 2 + $key_length) {
                die "Ciphertext too short: incomplete encrypted key";
            }

            # Split components
            my $encrypted_key  = substr($ciphertext, 2, $key_length);
            my $aes_ciphertext = substr($ciphertext, 2 + $key_length);

            # AES-GCM tag is 16 bytes at the end
            if (length($aes_ciphertext) < 16) {
                die "Ciphertext too short: missing authentication tag";
            }

            my $aes_data = substr($aes_ciphertext, 0, -16);
            my $aes_tag  = substr($aes_ciphertext, -16);

            # Decrypt session key with RSA-OAEP
            my $session_key = $private_key->decrypt(
                $encrypted_key,
                'oaep',
                'SHA256',
                $label,
            );

            # Decrypt data with AES-GCM
            $result = gcm_decrypt_verify(
                'AES',
                $session_key,
                AES_NONCE,
                undef,
                $aes_data,
                $aes_tag,
            );

            unless (defined $result) {
                die "AES-GCM authentication failed";
            }
        };
        $error = $@;
    }

    if ($error) {
        KubeSeal::Exception::DecryptionError->throw(
            message => "Decryption failed: $error",
        );
    }

    return $result;
}

sub decrypt_with_any_key {
    my (%args) = @_;

    my $ciphertext   = $args{ciphertext};
    my $private_keys = $args{private_keys};
    my $label        = $args{label} // '';

    unless (defined $private_keys && ref($private_keys) eq 'ARRAY' && @$private_keys) {
        KubeSeal::Exception::NoMatchingKeyError->throw(
            message    => 'No private keys provided',
            keys_tried => 0,
        );
    }

    my @errors;
    for my $key (@$private_keys) {
        my $result;
        eval {
            $result = decrypt(
                ciphertext  => $ciphertext,
                private_key => $key,
                label       => $label,
            );
        };

        if ($@) {
            push @errors, "$@";
        }
        else {
            return $result;
        }
    }

    KubeSeal::Exception::NoMatchingKeyError->throw(
        message    => "None of the " . scalar(@$private_keys) . " provided keys could decrypt the data. Last error: $errors[-1]",
        keys_tried => scalar(@$private_keys),
    );
}

1;

__END__

=head1 NAME

KubeSeal::Crypto - Hybrid RSA-OAEP + AES-256-GCM encryption for sealed secrets

=head1 SYNOPSIS

    use KubeSeal::Crypto qw(encrypt decrypt);
    use Crypt::PK::RSA;

    my $public_key = Crypt::PK::RSA->new('public.pem');
    my $private_key = Crypt::PK::RSA->new('private.pem');

    # Encrypt
    my $ciphertext = encrypt(
        plaintext  => 'my secret value',
        public_key => $public_key,
        label      => 'default/my-secret',  # scope label
    );

    # Decrypt
    my $plaintext = decrypt(
        ciphertext  => $ciphertext,
        private_key => $private_key,
        label       => 'default/my-secret',
    );

=head1 DESCRIPTION

Implements hybrid encryption compatible with Bitnami's kubeseal:

=over 4

=item * RSA-OAEP with SHA-256 hash and MGF1

=item * AES-256-GCM for data encryption

=item * Scope-dependent OAEP labels for binding

=back

B<Output format:>

    [2 bytes big-endian] [N bytes]         [M bytes]
    RSA ciphertext len   RSA-OAEP output   AES-GCM ciphertext+tag

=head1 FUNCTIONS

=head2 encrypt

    my $ciphertext = encrypt(
        plaintext  => $data,
        public_key => $rsa_public_key,
        label      => $scope_label,      # optional, default ''
    );

Encrypt data using hybrid RSA-OAEP + AES-GCM.

=head2 decrypt

    my $plaintext = decrypt(
        ciphertext  => $encrypted_data,
        private_key => $rsa_private_key,
        label       => $scope_label,
    );

Decrypt data. Label must match what was used for encryption.

=head2 decrypt_with_any_key

    my $plaintext = decrypt_with_any_key(
        ciphertext   => $encrypted_data,
        private_keys => \@keys,
        label        => $scope_label,
    );

Try decryption with multiple keys (for key rotation).

=head1 CONSTANTS

=over 4

=item * B<AES_KEY_SIZE> - 32 (256 bits)

=item * B<AES_NONCE> - 12 bytes of zeros

=back

=cut
