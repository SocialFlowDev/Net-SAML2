package Net::SAML2::Protocol::AuthnRequest;
use Moose;
use MooseX::Types::Moose qw /Str /;
use MooseX::Types::URI qw/ Uri /;
use MooseX::Types::Common::String qw/ NonEmptySimpleStr /;
use namespace::autoclean;

with 'Net::SAML2::Role::ProtocolMessage';

=head1 NAME

Net::SAML2::Protocol::AuthnRequest - SAML2 AuthnRequest object

=head1 SYNOPSIS

  my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
    issueinstant => DateTime->now,
    issuer       => $self->{id},
    destination  => $destination,
  );

=head1 METHODS

=cut

=head2 new( ... )

Constructor. Creates an instance of the AuthnRequest object. 

Arguments:

 * issuer - the SP's identity URI
 * destination - the IdP's identity URI

=cut

has 'issuer'        => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'destination'   => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'nameid_format' => (isa => NonEmptySimpleStr, is => 'ro', required => 1);

has 'provider_name'     => (isa => Str, is => 'ro');
has 'protocol_binding'  => (isa => Str, is => 'ro');
has 'ac_service_url'    => (isa => Uri, is => 'ro', coerce => 1);
has 'authn_context'     => (isa => Str, is => 'ro');

=head2 as_xml()

Returns the AuthnRequest as XML.

=cut

sub as_xml {
    my ($self) = @_;

    my $x = XML::Generator->new(':pretty');
    my $saml  = ['saml' => 'urn:oasis:names:tc:SAML:2.0:assertion'];
    my $samlp = ['samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol'];

    $x->xml(
        $x->AuthnRequest(
            $samlp,
            { Destination => $self->destination,
              ID => $self->id,
              IssueInstant => $self->issue_instant,
              ProviderName => $self->provider_name || 'Provider',
              defined($self->protocol_binding) ? (
                ProtocolBinding => $self->protocol_binding,
              ) : (),
              defined($self->ac_service_url) ? (
                AssertionConsumerServiceURL => $self->ac_service_url,
              ) : (),
              Version => '2.0' },
            $x->Issuer(
                $saml,
                $self->issuer,
            ),
            $x->NameIDPolicy(
                $samlp,
                { Format => $self->nameid_format },
            ),
            defined($self->authn_context) ? $x->RequestedAuthnContext(
                $samlp,
                { Comparison => 'exact' },
                $x->AuthnContextClassRef(
                    $saml,
                    $self->authn_context,
                ),
            ) : (),
        )
    );
}

__PACKAGE__->meta->make_immutable;
