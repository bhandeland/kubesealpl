#!/usr/bin/env perl

use strict;
use warnings;
use Test2::V0;
use Encode qw(encode);

use KubeSeal::Scope qw(
    STRICT NAMESPACE_WIDE CLUSTER_WIDE
    build_label scope_from_annotations
);

subtest 'scope constants' => sub {
    is(STRICT,         'strict',         'STRICT constant');
    is(NAMESPACE_WIDE, 'namespace-wide', 'NAMESPACE_WIDE constant');
    is(CLUSTER_WIDE,   'cluster-wide',   'CLUSTER_WIDE constant');
};

subtest 'build_label for CLUSTER_WIDE' => sub {
    my $label = build_label(scope => CLUSTER_WIDE);
    is($label, '', 'cluster-wide label is empty string');
};

subtest 'build_label for NAMESPACE_WIDE' => sub {
    my $label = build_label(
        scope     => NAMESPACE_WIDE,
        namespace => 'production',
    );
    is($label, encode('UTF-8', 'production'), 'namespace-wide label is namespace');
};

subtest 'build_label for STRICT' => sub {
    my $label = build_label(
        scope     => STRICT,
        namespace => 'default',
        name      => 'my-secret',
    );
    is($label, encode('UTF-8', 'default/my-secret'), 'strict label is namespace/name');
};

subtest 'build_label requires namespace for non-cluster-wide' => sub {
    my $died = 0;
    eval {
        build_label(scope => STRICT);
    };
    $died = 1 if $@;
    ok($died, 'dies without namespace for STRICT scope');
};

subtest 'build_label requires name for STRICT' => sub {
    my $died = 0;
    eval {
        build_label(scope => STRICT, namespace => 'default');
    };
    $died = 1 if $@;
    ok($died, 'dies without name for STRICT scope');
};

subtest 'scope_from_annotations' => sub {
    is(scope_from_annotations(undef), STRICT, 'default scope is STRICT');
    is(scope_from_annotations({}), STRICT, 'empty annotations gives STRICT');

    is(
        scope_from_annotations({ 'sealedsecrets.bitnami.com/cluster-wide' => 'true' }),
        CLUSTER_WIDE,
        'cluster-wide annotation'
    );

    is(
        scope_from_annotations({ 'sealedsecrets.bitnami.com/namespace-wide' => 'true' }),
        NAMESPACE_WIDE,
        'namespace-wide annotation'
    );

    # Cluster-wide takes precedence
    is(
        scope_from_annotations({
            'sealedsecrets.bitnami.com/cluster-wide'   => 'true',
            'sealedsecrets.bitnami.com/namespace-wide' => 'true',
        }),
        CLUSTER_WIDE,
        'cluster-wide takes precedence'
    );
};

done_testing;
