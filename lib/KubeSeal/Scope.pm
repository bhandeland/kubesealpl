package KubeSeal::Scope;

use strict;
use warnings;
use 5.026;

use Exporter 'import';
use Encode qw(encode);

use KubeSeal::Exception::ValidationError;

our @EXPORT_OK = qw(
    STRICT
    NAMESPACE_WIDE
    CLUSTER_WIDE
    build_label
    scope_from_annotations
    annotation_for_scope
);

our %EXPORT_TAGS = (
    all    => \@EXPORT_OK,
    scopes => [qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE)],
);

# Scope constants
use constant STRICT         => 'strict';
use constant NAMESPACE_WIDE => 'namespace-wide';
use constant CLUSTER_WIDE   => 'cluster-wide';

# Annotation keys
use constant ANNOTATION_CLUSTER_WIDE   => 'sealedsecrets.bitnami.com/cluster-wide';
use constant ANNOTATION_NAMESPACE_WIDE => 'sealedsecrets.bitnami.com/namespace-wide';

sub build_label {
    my (%args) = @_;

    my $scope     = $args{scope} // STRICT;
    my $namespace = $args{namespace};
    my $name      = $args{name};

    if ($scope eq CLUSTER_WIDE) {
        return '';
    }

    if (!defined $namespace || $namespace eq '') {
        KubeSeal::Exception::ScopeError->throw(
            message   => "namespace is required for scope $scope",
            scope     => $scope,
            namespace => $namespace,
            name      => $name,
        );
    }

    if ($scope eq NAMESPACE_WIDE) {
        return encode('UTF-8', $namespace);
    }

    # STRICT scope
    if (!defined $name || $name eq '') {
        KubeSeal::Exception::ScopeError->throw(
            message   => "name is required for scope $scope",
            scope     => $scope,
            namespace => $namespace,
            name      => $name,
        );
    }

    return encode('UTF-8', "$namespace/$name");
}

sub scope_from_annotations {
    my ($annotations) = @_;

    return STRICT unless defined $annotations && ref($annotations) eq 'HASH';

    # Cluster-wide takes precedence
    if (exists $annotations->{ANNOTATION_CLUSTER_WIDE()}
        && lc($annotations->{ANNOTATION_CLUSTER_WIDE()} // '') eq 'true')
    {
        return CLUSTER_WIDE;
    }

    if (exists $annotations->{ANNOTATION_NAMESPACE_WIDE()}
        && lc($annotations->{ANNOTATION_NAMESPACE_WIDE()} // '') eq 'true')
    {
        return NAMESPACE_WIDE;
    }

    return STRICT;
}

sub annotation_for_scope {
    my ($scope) = @_;

    return undef if $scope eq STRICT;

    if ($scope eq CLUSTER_WIDE) {
        return (ANNOTATION_CLUSTER_WIDE() => 'true');
    }

    if ($scope eq NAMESPACE_WIDE) {
        return (ANNOTATION_NAMESPACE_WIDE() => 'true');
    }

    return undef;
}

sub is_valid_scope {
    my ($scope) = @_;
    return defined $scope && ($scope eq STRICT || $scope eq NAMESPACE_WIDE || $scope eq CLUSTER_WIDE);
}

1;

__END__

=head1 NAME

KubeSeal::Scope - Sealing scope definitions and label generation

=head1 SYNOPSIS

    use KubeSeal::Scope qw(STRICT NAMESPACE_WIDE CLUSTER_WIDE build_label);

    # Build label for strict scope
    my $label = build_label(
        scope     => STRICT,
        namespace => 'default',
        name      => 'my-secret',
    );
    # Returns: "default/my-secret" (UTF-8 encoded bytes)

    # Build label for namespace-wide scope
    my $label = build_label(
        scope     => NAMESPACE_WIDE,
        namespace => 'production',
    );
    # Returns: "production"

    # Build label for cluster-wide scope
    my $label = build_label(scope => CLUSTER_WIDE);
    # Returns: ""

=head1 DESCRIPTION

Defines sealing scopes and generates OAEP labels for RSA encryption.
The scope determines how the sealed secret is bound:

=over 4

=item * B<STRICT> - Bound to specific namespace AND name (default)

=item * B<NAMESPACE_WIDE> - Bound to namespace only, any name

=item * B<CLUSTER_WIDE> - No binding, can be used anywhere

=back

=head1 FUNCTIONS

=head2 build_label

    my $label = build_label(
        scope     => $scope,
        namespace => $namespace,  # Required for STRICT and NAMESPACE_WIDE
        name      => $name,       # Required for STRICT only
    );

Build the OAEP label bytes for the given scope.

=head2 scope_from_annotations

    my $scope = scope_from_annotations($annotations_hashref);

Determine scope from Kubernetes annotations. Cluster-wide takes precedence.

=head2 annotation_for_scope

    my %annotation = annotation_for_scope($scope);

Get the appropriate annotation key/value for a scope.

=head1 CONSTANTS

=over 4

=item * B<STRICT> - 'strict'

=item * B<NAMESPACE_WIDE> - 'namespace-wide'

=item * B<CLUSTER_WIDE> - 'cluster-wide'

=back

=cut
