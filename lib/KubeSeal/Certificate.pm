package KubeSeal::Certificate;

use Moo;
use strict;
use warnings;
use 5.026;

use Crypt::OpenSSL::X509;
use Crypt::PK::RSA;
use HTTP::Tiny;
use Path::Tiny qw(path);
use POSIX qw(strftime);
use Time::Piece;

use KubeSeal::Exception::CertificateError;

use namespace::autoclean;

# Constants
use constant DEFAULT_CONTROLLER_NAMESPACE => 'kube-system';
use constant DEFAULT_CONTROLLER_NAME      => 'sealed-secrets-controller';
use constant CERT_ENDPOINT_PATH           => '/v1/cert.pem';

has 'pem_data' => (
    is       => 'ro',
    required => 1,
);

has 'certificate' => (
    is      => 'lazy',
    builder => '_build_certificate',
);

has 'public_key' => (
    is      => 'lazy',
    builder => '_build_public_key',
);

sub _build_certificate {
    my ($self) = @_;

    my $pem = $self->pem_data;

    my $cert;
    eval {
        $cert = Crypt::OpenSSL::X509->new_from_string($pem, Crypt::OpenSSL::X509::FORMAT_PEM());
    };
    if ($@) {
        KubeSeal::Exception::CertificateLoadError->throw(
            message => "Failed to parse certificate: $@",
        );
    }

    return $cert;
}

sub _build_public_key {
    my ($self) = @_;

    my $cert = $self->certificate;

    # Extract public key PEM from certificate
    my $pubkey_pem = $cert->pubkey();

    my $public_key;
    eval {
        $public_key = Crypt::PK::RSA->new(\$pubkey_pem);
    };
    if ($@) {
        KubeSeal::Exception::CertificateError->throw(
            message => "Failed to extract RSA public key from certificate: $@",
        );
    }

    return $public_key;
}

# Factory methods
sub from_file {
    my ($class, $filepath, %opts) = @_;

    my $validate = $opts{validate} // 1;
    my $file = path($filepath);

    unless ($file->exists) {
        KubeSeal::Exception::CertificateLoadError->throw(
            message          => "Certificate file not found: $filepath",
            certificate_path => $filepath,
        );
    }

    my $pem_data;
    eval {
        $pem_data = $file->slurp_raw;
    };
    if ($@) {
        KubeSeal::Exception::CertificateLoadError->throw(
            message          => "Failed to read certificate file: $@",
            certificate_path => $filepath,
        );
    }

    my $cert = $class->new(pem_data => $pem_data);

    if ($validate) {
        $cert->validate;
    }

    return $cert;
}

sub from_string {
    my ($class, $pem_string, %opts) = @_;

    my $validate = $opts{validate} // 1;

    my $cert = $class->new(pem_data => $pem_string);

    if ($validate) {
        $cert->validate;
    }

    return $cert;
}

sub from_url {
    my ($class, $url, %opts) = @_;

    my $validate   = $opts{validate} // 1;
    my $timeout    = $opts{timeout} // 30;
    my $verify_ssl = $opts{verify_ssl} // 1;

    my $http = HTTP::Tiny->new(
        timeout    => $timeout,
        verify_SSL => $verify_ssl,
    );

    my $response = $http->get($url);

    unless ($response->{success}) {
        KubeSeal::Exception::CertificateLoadError->throw(
            message => "Failed to fetch certificate from $url: $response->{status} $response->{reason}",
        );
    }

    my $pem_data = $response->{content};

    my $cert = $class->new(pem_data => $pem_data);

    if ($validate) {
        $cert->validate;
    }

    return $cert;
}

sub from_cluster {
    my ($class, %opts) = @_;

    my $controller_name      = $opts{controller_name} // DEFAULT_CONTROLLER_NAME;
    my $controller_namespace = $opts{controller_namespace} // DEFAULT_CONTROLLER_NAMESPACE;
    my $validate             = $opts{validate} // 1;

    # Try kubectl proxy or direct service access
    # This is a simplified implementation - in practice you'd use kubernetes client
    my $url = "http://localhost:8001/api/v1/namespaces/$controller_namespace/services/$controller_name/proxy" . CERT_ENDPOINT_PATH;

    return $class->from_url($url, validate => $validate, %opts);
}

# Instance methods
sub validate {
    my ($self, %opts) = @_;

    my $check_expiry   = $opts{check_expiry} // 1;
    my $reference_time = $opts{reference_time};

    return unless $check_expiry;

    my $cert = $self->certificate;

    # Get validity dates
    my $not_before_str = $cert->notBefore;
    my $not_after_str  = $cert->notAfter;

    # Parse dates (format: "Dec 31 23:59:59 2025 GMT")
    my $not_before = _parse_cert_date($not_before_str);
    my $not_after  = _parse_cert_date($not_after_str);

    # Use provided reference time or current time
    my $now = $reference_time // time();

    if ($now < $not_before) {
        KubeSeal::Exception::CertificateNotYetValidError->throw(
            message    => "Certificate not yet valid",
            not_before => $not_before_str,
        );
    }

    if ($now > $not_after) {
        KubeSeal::Exception::CertificateExpiredError->throw(
            message   => "Certificate has expired",
            not_after => $not_after_str,
        );
    }

    return 1;
}

sub is_valid {
    my ($self) = @_;

    eval {
        $self->validate;
    };
    return $@ ? 0 : 1;
}

sub not_before {
    my ($self) = @_;
    return $self->certificate->notBefore;
}

sub not_after {
    my ($self) = @_;
    return $self->certificate->notAfter;
}

sub subject {
    my ($self) = @_;
    return $self->certificate->subject;
}

sub issuer {
    my ($self) = @_;
    return $self->certificate->issuer;
}

sub fingerprint {
    my ($self, $algorithm) = @_;
    $algorithm //= 'sha256';
    return $self->certificate->fingerprint_sha256 if $algorithm eq 'sha256';
    return $self->certificate->fingerprint_sha1 if $algorithm eq 'sha1';
    return $self->certificate->fingerprint_md5 if $algorithm eq 'md5';
    return $self->certificate->fingerprint_sha256;
}

# Helper function to parse certificate date strings
sub _parse_cert_date {
    my ($date_str) = @_;

    # Format: "Dec 31 23:59:59 2025 GMT"
    # Try to parse using Time::Piece
    my $tp;
    eval {
        $tp = Time::Piece->strptime($date_str, "%b %d %H:%M:%S %Y %Z");
    };
    if ($@) {
        # Fallback: try without timezone
        eval {
            $date_str =~ s/\s+GMT\s*$//;
            $tp = Time::Piece->strptime($date_str, "%b %d %H:%M:%S %Y");
        };
    }

    return $tp ? $tp->epoch : time();
}

1;

__END__

=head1 NAME

KubeSeal::Certificate - X.509 certificate loading and validation

=head1 SYNOPSIS

    use KubeSeal::Certificate;

    # Load from file
    my $cert = KubeSeal::Certificate->from_file('/path/to/cert.pem');

    # Load from URL
    my $cert = KubeSeal::Certificate->from_url('https://controller/v1/cert.pem');

    # Load from string
    my $cert = KubeSeal::Certificate->from_string($pem_data);

    # Access public key for encryption
    my $public_key = $cert->public_key;

    # Validate certificate
    $cert->validate;

=head1 DESCRIPTION

Loads and validates X.509 certificates for use with sealed secrets.
Supports loading from files, URLs, and Kubernetes clusters.

=head1 METHODS

=head2 from_file

    my $cert = KubeSeal::Certificate->from_file($path, validate => 1);

Load certificate from a PEM file.

=head2 from_url

    my $cert = KubeSeal::Certificate->from_url($url,
        validate   => 1,
        timeout    => 30,
        verify_ssl => 1,
    );

Fetch certificate from an HTTP(S) URL.

=head2 from_string

    my $cert = KubeSeal::Certificate->from_string($pem_data);

Parse certificate from a PEM string.

=head2 from_cluster

    my $cert = KubeSeal::Certificate->from_cluster(
        controller_name      => 'sealed-secrets-controller',
        controller_namespace => 'kube-system',
    );

Fetch certificate from Kubernetes cluster (requires kubectl proxy).

=head2 validate

    $cert->validate(check_expiry => 1);

Validate certificate validity period. Throws exception if invalid.

=head2 is_valid

    if ($cert->is_valid) { ... }

Returns true if certificate is currently valid.

=head2 public_key

    my $key = $cert->public_key;

Returns the Crypt::PK::RSA public key object.

=cut
