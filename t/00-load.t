#!/usr/bin/env perl

use strict;
use warnings;
use Test2::V0;

# Test that all modules can be loaded

my @modules = qw(
    KubeSeal
    KubeSeal::Types
    KubeSeal::Scope
    KubeSeal::Crypto
    KubeSeal::Certificate
    KubeSeal::PrivateKey
    KubeSeal::Sealer
    KubeSeal::Unsealer
    KubeSeal::Model::ObjectMeta
    KubeSeal::Model::Secret
    KubeSeal::Model::SealedSecret
    KubeSeal::Exception::Base
    KubeSeal::Exception::CryptoError
    KubeSeal::Exception::CertificateError
    KubeSeal::Exception::KeyError
    KubeSeal::Exception::ValidationError
);

for my $module (@modules) {
    require_ok($module);
}

done_testing;
