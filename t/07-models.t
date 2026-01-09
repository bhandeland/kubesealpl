#!/usr/bin/env perl

use strict;
use warnings;
use Test2::V0;
use MIME::Base64 qw(encode_base64 decode_base64);

use KubeSeal::Model::ObjectMeta;
use KubeSeal::Model::Secret;
use KubeSeal::Model::SealedSecret;

subtest 'ObjectMeta' => sub {
    my $meta = KubeSeal::Model::ObjectMeta->new(
        name        => 'my-secret',
        namespace   => 'default',
        labels      => { app => 'test' },
        annotations => { key => 'value' },
    );

    is($meta->name,      'my-secret', 'name accessor');
    is($meta->namespace, 'default',   'namespace accessor');
    is($meta->labels->{app}, 'test',  'labels accessor');

    my $hash = $meta->to_hash;
    is($hash->{name},      'my-secret', 'to_hash name');
    is($hash->{namespace}, 'default',   'to_hash namespace');
};

subtest 'Secret from_string_data' => sub {
    my $secret = KubeSeal::Model::Secret->from_string_data(
        name      => 'my-secret',
        namespace => 'default',
        data      => { password => 'secret123' },
    );

    is($secret->name,      'my-secret', 'name accessor');
    is($secret->namespace, 'default',   'namespace accessor');
    is($secret->type,      'Opaque',    'default type');
};

subtest 'Secret from_data with binary' => sub {
    my $secret = KubeSeal::Model::Secret->from_data(
        name      => 'my-secret',
        namespace => 'default',
        data      => { password => 'secret123' },
    );

    my $decoded = $secret->get_data_decoded;
    is($decoded->{password}, 'secret123', 'data is properly encoded/decoded');
};

subtest 'Secret to_yaml and from_yaml' => sub {
    my $secret = KubeSeal::Model::Secret->from_data(
        name      => 'test-secret',
        namespace => 'production',
        data      => { api_key => 'abc123' },
        type      => 'Opaque',
    );

    my $yaml = $secret->to_yaml;
    ok($yaml =~ /apiVersion: v1/, 'yaml contains apiVersion');
    ok($yaml =~ /kind: Secret/, 'yaml contains kind');
    ok($yaml =~ /name: test-secret/, 'yaml contains name');

    my $parsed = KubeSeal::Model::Secret->from_yaml($yaml);
    is($parsed->name, 'test-secret', 'parsed name matches');
};

subtest 'SealedSecret' => sub {
    my $sealed = KubeSeal::Model::SealedSecret->new_sealed(
        name           => 'my-secret',
        namespace      => 'default',
        encrypted_data => { password => encode_base64('encrypted-data', '') },
        type           => 'Opaque',
    );

    is($sealed->name,      'my-secret', 'name accessor');
    is($sealed->namespace, 'default',   'namespace accessor');

    my $yaml = $sealed->to_yaml;
    ok($yaml =~ /apiVersion: bitnami\.com\/v1alpha1/, 'yaml contains apiVersion');
    ok($yaml =~ /kind: SealedSecret/, 'yaml contains kind');
};

subtest 'SealedSecret from_yaml' => sub {
    my $yaml = <<'YAML';
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-sealed
  namespace: testing
spec:
  encryptedData:
    password: YWJjZGVm
YAML

    my $sealed = KubeSeal::Model::SealedSecret->from_yaml($yaml);
    is($sealed->name, 'test-sealed', 'parsed name');
    is($sealed->namespace, 'testing', 'parsed namespace');
    is($sealed->encrypted_data->{password}, 'YWJjZGVm', 'encrypted data preserved');
};

done_testing;
