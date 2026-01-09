#!/usr/bin/env perl

use strict;
use warnings;
use 5.026;

use KubeSeal::Sealer;
use KubeSeal::Scope qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE);
use Getopt::Long;

my $cert_file;
my $cert_url;
my $namespace = 'default';
my $name;
my $scope     = 'strict';
my $type      = 'Opaque';
my @data_pairs;

GetOptions(
    'cert-file=s'  => \$cert_file,
    'cert-url=s'   => \$cert_url,
    'namespace=s'  => \$namespace,
    'name=s'       => \$name,
    'scope=s'      => \$scope,
    'type=s'       => \$type,
    'data=s'       => \@data_pairs,
) or die "Usage: $0 --cert-file|--cert-url CERT --name NAME --data key=value [...]\n";

die "Certificate (--cert-file or --cert-url) is required\n" unless $cert_file || $cert_url;
die "Secret name (--name) is required\n" unless $name;
die "At least one --data key=value is required\n" unless @data_pairs;

# Map scope string to constant
my %scope_map = (
    'strict'         => STRICT,
    'namespace-wide' => NAMESPACE_WIDE,
    'cluster-wide'   => CLUSTER_WIDE,
);
my $seal_scope = $scope_map{$scope} // die "Invalid scope: $scope\n";

# Create sealer
my $sealer;
if ($cert_file) {
    $sealer = KubeSeal::Sealer->from_certificate_file($cert_file);
}
else {
    $sealer = KubeSeal::Sealer->from_certificate_url($cert_url);
}

# Parse data pairs
my %data;
for my $pair (@data_pairs) {
    my ($key, $value) = split /=/, $pair, 2;
    die "Invalid data format: $pair (expected key=value)\n" unless defined $value;
    $data{$key} = $value;
}

# Seal the secret
my $sealed = $sealer->seal(
    name      => $name,
    namespace => $namespace,
    data      => \%data,
    scope     => $seal_scope,
    type      => $type,
);

# Output YAML
print $sealed->to_yaml;

__END__

=head1 NAME

seal_secret.pl - Seal a Kubernetes secret

=head1 SYNOPSIS

    # Seal with strict scope (default)
    perl seal_secret.pl \
        --cert-file /path/to/cert.pem \
        --name my-secret \
        --namespace default \
        --data password=supersecret \
        --data apikey=key123

    # Seal with cluster-wide scope
    perl seal_secret.pl \
        --cert-url https://controller/v1/cert.pem \
        --name global-secret \
        --scope cluster-wide \
        --data token=abc123

=head1 OPTIONS

    --cert-file     Path to certificate PEM file
    --cert-url      URL to fetch certificate from
    --name          Secret name (required)
    --namespace     Kubernetes namespace (default: default)
    --scope         Sealing scope: strict, namespace-wide, cluster-wide
    --type          Secret type (default: Opaque)
    --data          Key=value pairs (can be specified multiple times)

=cut
