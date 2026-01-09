requires 'perl', '5.026';

# OO Framework
requires 'Moo', '2.005';
requires 'Type::Tiny', '2.000';
requires 'Types::Standard';
requires 'namespace::autoclean', '0.29';

# Cryptography
requires 'CryptX', '0.080';
requires 'Crypt::OpenSSL::X509', '1.915';

# Data Formats
requires 'YAML::XS', '0.88';
requires 'MIME::Base64';  # Core module

# HTTP
requires 'HTTP::Tiny';    # Core module
requires 'IO::Socket::SSL', '2.084';
requires 'Mozilla::CA';

# Exception handling
requires 'Try::Tiny', '0.31';
requires 'Throwable', '1.001';

# Utilities
requires 'Path::Tiny';

on 'test' => sub {
    requires 'Test2::V0';
    requires 'Test::Exception';
    requires 'Test::Deep';
};

on 'develop' => sub {
    requires 'Dist::Zilla';
    requires 'Dist::Zilla::Plugin::MetaProvides::Package';
    requires 'Dist::Zilla::Plugin::PodWeaver';
    requires 'Dist::Zilla::Plugin::Test::Compile';
    requires 'Dist::Zilla::Plugin::Test::ReportPrereqs';
};
