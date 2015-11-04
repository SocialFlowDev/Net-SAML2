package Net::SAML2::SP;
use Moose;
use MooseX::Types::Moose qw/ Str /;
use MooseX::Types::URI qw/ Uri /;
use namespace::autoclean;

=head1 NAME

Net::SAML2::SP - SAML Service Provider object

=head1 SYNOPSIS

  my $sp = Net::SAML2::SP->new(
    id   => 'http://localhost:3000',
    url  => 'http://localhost:3000',
    cert => 'sign-nopw-cert.pem',
  );

=head1 METHODS

=cut

use Crypt::OpenSSL::X509;
use XML::Generator;

=head2 new( ... )

Constructor. Create an SP object. 

Arguments:

 * url    - the base for all SP service URLs
 * id     - the SP's identity URI. 
 * cert   - path to the signing certificate
 * cacert - path to the CA certificate for verification

 * org_name         - the SP organisation name
 * org_display_name - the SP organisation display name
 * org_contact      - an SP contact email address

 * soap          - bindings:SOAP location          ( $url/saml/slo-soap )
 * http_redirect - bindings:HTTP-Redirect location ( $url/saml/sls-redirect-response )
 * http_post     - bindings:HTTP-POST location     ( $url/saml/consumer-post
 * http_artifact - bindings:HTTP-Artifact location ( $url/saml/consumer-artifact )


=cut

has 'url'    => (isa => Uri, is => 'ro', required => 1, coerce => 1);
has 'id'     => (isa => Str, is => 'ro', required => 1);
has 'cert'   => (isa => Str, is => 'ro', required => 1);
has 'cacert' => (isa => Str, is => 'ro', required => 1);

has 'org_name'         => (isa => Str, is => 'ro', required => 1);
has 'org_display_name' => (isa => Str, is => 'ro', required => 1);
has 'org_contact'      => (isa => Str, is => 'ro', required => 1);

has id_prefix => (isa => Str, is => 'ro');

has 'soap' => (
    isa     => Str, 
    is      => 'ro',
    lazy    => 1,
    default => sub { sprintf( "%s/saml/slo-soap", shift->url ) }
);

has 'http_redirect' => (
    isa => Str,
    is => 'ro',
    lazy    => 1,
    default => sub { sprintf( "%s/saml/sls-redirect-response", shift->url ) }
);

has 'http_post' => (
    isa => Str, 
    is => 'ro',
    lazy    => 1,
    default => sub { sprintf( "%s/saml/consumer-post", shift->url ) }
);

has 'http_artifact' => (
    isa => Str,
    is => 'ro', 
    lazy    => 1,
    default => sub { sprintf( "%s/saml/consumer-artifact", shift->url ) }
);

has '_cert_text' => (isa => Str, is => 'rw', required => 0);

sub BUILD {
    my ($self) = @_;

    my $cert = Crypt::OpenSSL::X509->new_from_file($self->cert);
    my $text = $cert->as_string;
    $text =~ s/-----[^-]*-----//gm;
    $self->_cert_text($text);
        
    return $self;
}

=head2 authn_request($destination)

Returns an AuthnRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

=cut

sub authn_request {
    my ($self, $destination, $nameid_format, %opt) = @_;
        
    my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
        %opt,
        issueinstant  => DateTime->now,
        issuer        => $self->id,
        destination   => $destination,
        nameid_format => $nameid_format,
        id_prefix     => $self->id_prefix,
    );
        
    return $authnreq;
}

=head2 logout_request($destination, $nameid, $nameid_format, $session)

Returns a LogoutRequest object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

Also requires the nameid (+format) and session to be logged out. 

=cut

sub logout_request {
    my ($self, $destination, $nameid, $nameid_format, $session) = @_;

    my $logout_req = Net::SAML2::Protocol::LogoutRequest->new(
        issuer        => $self->id,
        destination   => $destination,
        nameid        => $nameid,
        nameid_format => $nameid_format,
        session       => $session,
    );

    return $logout_req;
}

=head2 logout_response($destination, $status, $response_to)

Returns a LogoutResponse object created by this SP, intended for the
given destination, which should be the identity URI of the IdP.

Also requires the status and the ID of the corresponding
LogoutRequest.

=cut

sub logout_response {
    my ($self, $destination, $status, $response_to) = @_;

    my $status_uri = Net::SAML2::Protocol::LogoutResponse->status_uri($status);
    my $logout_req = Net::SAML2::Protocol::LogoutResponse->new(
        issuer      => $self->id,
        destination => $destination,
        status      => $status_uri,
        response_to => $response_to,
    );

    return $logout_req;
}

=head2 artifact_request($destination, $artifact)

Returns an ArtifactResolve request object created by this SP, intended
for the given destination, which should be the identity URI of the
IdP.

=cut

sub artifact_request {
    my ($self, $destination, $artifact) = @_;
        
    my $artifact_request = Net::SAML2::Protocol::ArtifactResolve->new(
        issuer       => $self->id,
        destination  => $destination,
        artifact     => $artifact,
        issueinstant => DateTime->now,
    );
        
    return $artifact_request;
}

=head2 sso_redirect_binding($idp, $param)

Returns a Redirect binding object for this SP, configured against the
given IDP for Single Sign On. $param specifies the name of the query
parameter involved - typically SAMLRequest.

=cut

sub sso_redirect_binding {
    my ($self, $idp, $param, $destination) = @_;

    my $url = $destination // $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');    
    my $redirect = Net::SAML2::Binding::Redirect->new(
        url   => $url,
        cert  => $idp->cert('signing'),
        key   => $self->cert,
        param => $param,
    );
        
    return $redirect;
}

=head2 slo_redirect_binding

Returns a Redirect binding object for this SP, configured against the
given IDP for Single Log Out. $param specifies the name of the query
parameter involved - typically SAMLRequest or SAMLResponse.

=cut

sub slo_redirect_binding {
    my ($self, $idp, $param) = @_;
        
    my $redirect = Net::SAML2::Binding::Redirect->new(
        url   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        cert  => $idp->cert('signing'),
        key   => $self->cert,
        param => $param,
    );
        
    return $redirect;
}

=head2 soap_binding

Returns a SOAP binding object for this SP, with a destination of the
given URL and signing certificate.

XXX UA

=cut

sub soap_binding {
    my ($self, $ua, $idp_url, $idp_cert) = @_;

    my $soap = Net::SAML2::Binding::SOAP->new(
        ua       => $ua,
        key      => $self->cert,
        cert     => $self->cert,
        url      => $idp_url,
        idp_cert => $idp_cert,
        cacert   => $self->cacert,
    );
        
    return $soap;
}

=head2 post_binding

Returns a POST binding object for this SP.

=cut

sub post_binding {
    my ($self) = @_;
        
    my $post = Net::SAML2::Binding::POST->new(
        cacert => $self->cacert,
    );
        
    return $post;
}

=head2 metadata

Returns the metadata XML document for this SP.

=cut

sub metadata {
    my ($self) = @_;

    my $x = XML::Generator->new(':pretty', conformance => 'loose');
    my $md = ['md' => 'urn:oasis:names:tc:SAML:2.0:metadata'];
    my $ds = ['ds' => 'http://www.w3.org/2000/09/xmldsig#'];

    $x->EntityDescriptor(
        $md,
        {
            entityID => $self->id },
        $x->SPSSODescriptor(
            $md,
            { AuthnRequestsSigned => '1',
              WantAssertionsSigned => '1',
              errorURL => $self->url . '/saml/error',
              protocolSupportEnumeration => 'urn:oasis:names:tc:SAML:2.0:protocol' },
            $x->KeyDescriptor(
                $md,
                {
                    use => 'signing' },
                $x->KeyInfo(
                    $ds,
                    $x->X509Data(
                        $ds,
                        $x->X509Certificate(
                            $ds,
                            $self->_cert_text,
                        )
                    )
                )
            ),
            $x->SingleLogoutService(
                $md,
                { Binding => 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
                  Location => $self->soap,
              },
            ),
            $x->SingleLogoutService(
                $md,
                { Binding => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                  Location => $self->http_redirect,
                },
            ),
            $x->AssertionConsumerService(
                $md,
                { Binding => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                  Location => $self->http_post,
                  index => '1',
                  isDefault => 'true' },
            ),
            $x->AssertionConsumerService(
                $md,
                { Binding => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
                  Location => $self->http_artifact,
                  index => '2',
                  isDefault => 'false' },
            ),
        ),
        $x->Organization(
            $md,
            $x->OrganizationName(
                $md,
                {
                    'xml:lang' => 'en' },
                $self->org_name,
            ),
            $x->OrganizationDisplayName(
                $md,
                {
                    'xml:lang' => 'en' },
                $self->org_display_name,
            ),
            $x->OrganizationURL(
                $md,
                {
                    'xml:lang' => 'en' },
                $self->url
            )
        ),
        $x->ContactPerson(
            $md,
            {
                contactType => 'other' },
            $x->Company(
                $md,
                $self->org_display_name,
            ),
            $x->EmailAddress(
                $md,
                $self->org_contact,
            ),
        )
    );
}

__PACKAGE__->meta->make_immutable;
