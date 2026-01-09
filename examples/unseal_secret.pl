#!/usr/bin/env perl

use strict;
use warnings;
use 5.026;

use KubeSeal::Unsealer;
use KubeSeal::Model::SealedSecret;
use Getopt::Long;

my $key_file;
my $key_dir;
my $password;
my $yaml_file;

GetOptions(
    'key-file=s' => \$key_file,
    'key-dir=s'  => \$key_dir,
    'password=s' => \$password,
    'yaml=s'     => \$yaml_file,
) or die "Usage: $0 --key-file|--key-dir KEY --yaml SEALED_SECRET.yaml\n";

die "Private key (--key-file or --key-dir) is required\n" unless $key_file || $key_dir;
die "YAML file (--yaml) is required\n" unless $yaml_file;

# Create unsealer
my $unsealer;
if ($key_file) {
    $unsealer = KubeSeal::Unsealer->from_private_key_file(
        $key_file,
        password => $password,
    );
}
else {
    $unsealer = KubeSeal::Unsealer->from_private_keys_directory(
        $key_dir,
        password => $password,
    );
}

# Load sealed secret
open my $fh, '<', $yaml_file or die "Cannot open $yaml_file: $!\n";
my $yaml_content = do { local $/; <$fh> };
close $fh;

my $sealed = KubeSeal::Model::SealedSecret->from_yaml($yaml_content);

# Unseal
my $secret = $unsealer->unseal($sealed);

# Output decrypted secret YAML
print $secret->to_yaml;

# Or show individual values
print STDERR "\nDecrypted values:\n";
my $data = $secret->get_data_decoded;
for my $key (sort keys %$data) {
    print STDERR "  $key: $data->{$key}\n";
}

__END__

=head1 NAME

unseal_secret.pl - Unseal a Kubernetes SealedSecret

=head1 SYNOPSIS

    # Unseal with single key
    perl unseal_secret.pl \
        --key-file /path/to/private.pem \
        --yaml sealed-secret.yaml

    # Unseal with multiple keys (key rotation)
    perl unseal_secret.pl \
        --key-dir /path/to/keys/ \
        --yaml sealed-secret.yaml

    # With password-protected key
    perl unseal_secret.pl \
        --key-file /path/to/encrypted.pem \
        --password mypassword \
        --yaml sealed-secret.yaml

=head1 OPTIONS

    --key-file      Path to private key PEM file
    --key-dir       Directory containing private key files
    --password      Password for encrypted private keys
    --yaml          Path to SealedSecret YAML file

=head1 OUTPUT

Prints the decrypted Secret as YAML to stdout.
Also prints individual decrypted values to stderr.

=cut
