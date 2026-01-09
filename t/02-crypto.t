#!/usr/bin/env perl

use strict;
use warnings;
use Test2::V0;
use Crypt::PK::RSA;

use KubeSeal::Crypto qw(encrypt decrypt decrypt_with_any_key AES_KEY_SIZE AES_NONCE);

# Generate test RSA key pair
my $rsa = Crypt::PK::RSA->new();
$rsa->generate_key(2048);

my $private_key = $rsa;
my $public_key  = Crypt::PK::RSA->new(\$rsa->export_key_pem('public'));

subtest 'constants' => sub {
    is(AES_KEY_SIZE, 32, 'AES key size is 32 bytes');
    is(length(AES_NONCE), 12, 'AES nonce is 12 bytes');
    is(AES_NONCE, "\x00" x 12, 'AES nonce is all zeros');
};

subtest 'encrypt and decrypt round trip' => sub {
    my $plaintext = 'This is a secret message!';
    my $label = 'default/my-secret';

    my $ciphertext = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => $label,
    );

    ok(defined $ciphertext, 'encryption produces output');
    ok(length($ciphertext) > length($plaintext), 'ciphertext is longer than plaintext');

    my $decrypted = decrypt(
        ciphertext  => $ciphertext,
        private_key => $private_key,
        label       => $label,
    );

    is($decrypted, $plaintext, 'decrypted text matches original');
};

subtest 'different labels fail decryption' => sub {
    my $plaintext = 'Secret data';

    my $ciphertext = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => 'namespace1/secret1',
    );

    my $died = 0;
    eval {
        decrypt(
            ciphertext  => $ciphertext,
            private_key => $private_key,
            label       => 'namespace2/secret2',  # Wrong label
        );
    };
    $died = 1 if $@;

    ok($died, 'decryption fails with wrong label');
};

subtest 'empty label (cluster-wide)' => sub {
    my $plaintext = 'Cluster-wide secret';

    my $ciphertext = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => '',
    );

    my $decrypted = decrypt(
        ciphertext  => $ciphertext,
        private_key => $private_key,
        label       => '',
    );

    is($decrypted, $plaintext, 'empty label works');
};

subtest 'binary data' => sub {
    my $plaintext = "\x00\x01\x02\xFF\xFE\xFD";

    my $ciphertext = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => 'test',
    );

    my $decrypted = decrypt(
        ciphertext  => $ciphertext,
        private_key => $private_key,
        label       => 'test',
    );

    is($decrypted, $plaintext, 'binary data preserved');
};

subtest 'decrypt_with_any_key' => sub {
    my $plaintext = 'Multi-key test';

    my $ciphertext = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => '',
    );

    # Create another key pair
    my $rsa2 = Crypt::PK::RSA->new();
    $rsa2->generate_key(2048);

    my $decrypted = decrypt_with_any_key(
        ciphertext   => $ciphertext,
        private_keys => [$rsa2, $private_key],  # Right key is second
        label        => '',
    );

    is($decrypted, $plaintext, 'decrypt_with_any_key finds right key');
};

subtest 'decrypt_with_any_key - no matching key' => sub {
    my $plaintext = 'No match test';

    my $ciphertext = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => '',
    );

    # Create different keys
    my $rsa2 = Crypt::PK::RSA->new();
    $rsa2->generate_key(2048);
    my $rsa3 = Crypt::PK::RSA->new();
    $rsa3->generate_key(2048);

    my $died = 0;
    eval {
        decrypt_with_any_key(
            ciphertext   => $ciphertext,
            private_keys => [$rsa2, $rsa3],  # Neither matches
            label        => '',
        );
    };
    $died = 1 if $@;

    ok($died, 'dies when no key matches');
};

done_testing;
