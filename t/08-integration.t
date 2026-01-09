#!/usr/bin/env perl

use strict;
use warnings;
use Test2::V0;
use Crypt::PK::RSA;
use Crypt::OpenSSL::X509;
use File::Temp qw(tempfile);

use KubeSeal::Sealer;
use KubeSeal::Unsealer;
use KubeSeal::Scope qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE);
use KubeSeal::Model::Secret;

# Generate test RSA key pair and self-signed certificate
my $rsa = Crypt::PK::RSA->new();
$rsa->generate_key(2048);

my $private_key_pem = $rsa->export_key_pem('private');
my $public_key_pem  = $rsa->export_key_pem('public');

# Create a minimal self-signed certificate for testing
# We'll use the Sealer's from_certificate_pem with just the public key
# For this test, we'll create a mock certificate

# Write keys to temp files
my ($priv_fh, $priv_file) = tempfile(SUFFIX => '.pem', UNLINK => 1);
print $priv_fh $private_key_pem;
close $priv_fh;

# For testing, we need to create a self-signed certificate
# Using openssl command or generating inline
# For simplicity, let's test with direct key usage

subtest 'full seal/unseal round trip with STRICT scope' => sub {
    # Create sealer using raw public key (bypass certificate for testing)
    my $unsealer = KubeSeal::Unsealer->from_private_key_file($priv_file);

    # Use internal crypto directly for this test
    use KubeSeal::Crypto qw(encrypt decrypt);
    use KubeSeal::Scope qw(build_label);
    use MIME::Base64 qw(encode_base64 decode_base64);

    my $namespace = 'default';
    my $name      = 'my-secret';
    my $scope     = STRICT;

    my $label = build_label(
        scope     => $scope,
        namespace => $namespace,
        name      => $name,
    );

    my $plaintext = 'supersecret';
    my $public_key = Crypt::PK::RSA->new(\$public_key_pem);

    my $encrypted = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => $label,
    );

    ok(defined $encrypted, 'encryption produces output');

    # Create a SealedSecret manually
    use KubeSeal::Model::SealedSecret;
    my $sealed = KubeSeal::Model::SealedSecret->new_sealed(
        name           => $name,
        namespace      => $namespace,
        encrypted_data => { password => encode_base64($encrypted, '') },
    );

    # Unseal it
    my $secret = $unsealer->unseal($sealed, scope => $scope);

    is($secret->name, $name, 'unsealed secret has correct name');
    is($secret->namespace, $namespace, 'unsealed secret has correct namespace');

    my $decoded = $secret->get_data_decoded;
    is($decoded->{password}, $plaintext, 'unsealed data matches original');
};

subtest 'seal/unseal with NAMESPACE_WIDE scope' => sub {
    use KubeSeal::Crypto qw(encrypt);
    use KubeSeal::Scope qw(build_label);
    use MIME::Base64 qw(encode_base64);

    my $unsealer = KubeSeal::Unsealer->from_private_key_file($priv_file);

    my $namespace = 'production';
    my $name      = 'db-secret';
    my $scope     = NAMESPACE_WIDE;

    my $label = build_label(
        scope     => $scope,
        namespace => $namespace,
        name      => $name,
    );

    my $plaintext = 'db-password';
    my $public_key = Crypt::PK::RSA->new(\$public_key_pem);

    my $encrypted = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => $label,
    );

    use KubeSeal::Model::SealedSecret;
    my $sealed = KubeSeal::Model::SealedSecret->new_sealed(
        name           => $name,
        namespace      => $namespace,
        encrypted_data => { db_pass => encode_base64($encrypted, '') },
        annotations    => { 'sealedsecrets.bitnami.com/namespace-wide' => 'true' },
    );

    my $secret = $unsealer->unseal($sealed);  # Scope auto-detected

    my $decoded = $secret->get_data_decoded;
    is($decoded->{db_pass}, $plaintext, 'namespace-wide unseal works');
};

subtest 'seal/unseal with CLUSTER_WIDE scope' => sub {
    use KubeSeal::Crypto qw(encrypt);
    use KubeSeal::Scope qw(build_label);
    use MIME::Base64 qw(encode_base64);

    my $unsealer = KubeSeal::Unsealer->from_private_key_file($priv_file);

    my $namespace = 'any-namespace';
    my $name      = 'global-secret';
    my $scope     = CLUSTER_WIDE;

    my $label = build_label(
        scope     => $scope,
        namespace => $namespace,
        name      => $name,
    );

    my $plaintext = 'global-api-key';
    my $public_key = Crypt::PK::RSA->new(\$public_key_pem);

    my $encrypted = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => $label,
    );

    use KubeSeal::Model::SealedSecret;
    my $sealed = KubeSeal::Model::SealedSecret->new_sealed(
        name           => $name,
        namespace      => $namespace,
        encrypted_data => { api_key => encode_base64($encrypted, '') },
        annotations    => { 'sealedsecrets.bitnami.com/cluster-wide' => 'true' },
    );

    my $secret = $unsealer->unseal($sealed);

    my $decoded = $secret->get_data_decoded;
    is($decoded->{api_key}, $plaintext, 'cluster-wide unseal works');
};

subtest 'multiple keys for rotation' => sub {
    use KubeSeal::Crypto qw(encrypt);
    use KubeSeal::Scope qw(build_label);
    use MIME::Base64 qw(encode_base64);

    # Generate a second key pair
    my $rsa2 = Crypt::PK::RSA->new();
    $rsa2->generate_key(2048);
    my $private_key_pem2 = $rsa2->export_key_pem('private');

    my ($priv_fh2, $priv_file2) = tempfile(SUFFIX => '.pem', UNLINK => 1);
    print $priv_fh2 $private_key_pem2;
    close $priv_fh2;

    # Create unsealer with both keys
    use KubeSeal::PrivateKey;
    my $key1 = KubeSeal::PrivateKey->from_file($priv_file);
    my $key2 = KubeSeal::PrivateKey->from_file($priv_file2);

    my $unsealer = KubeSeal::Unsealer->new(private_keys => [$key1, $key2]);

    is($unsealer->key_count, 2, 'unsealer has 2 keys');

    # Encrypt with first public key
    my $public_key = Crypt::PK::RSA->new(\$public_key_pem);
    my $plaintext = 'rotated-secret';

    my $encrypted = encrypt(
        plaintext  => $plaintext,
        public_key => $public_key,
        label      => '',
    );

    use KubeSeal::Model::SealedSecret;
    my $sealed = KubeSeal::Model::SealedSecret->new_sealed(
        name           => 'rotation-test',
        namespace      => 'default',
        encrypted_data => { secret => encode_base64($encrypted, '') },
        annotations    => { 'sealedsecrets.bitnami.com/cluster-wide' => 'true' },
    );

    my $secret = $unsealer->unseal($sealed);

    my $decoded = $secret->get_data_decoded;
    is($decoded->{secret}, $plaintext, 'multi-key unsealer works');
};

done_testing;
