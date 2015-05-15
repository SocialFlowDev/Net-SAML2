package Net::SAML2::Binding::POST;
use Moose;
use MooseX::Types::Moose qw/ Str /;
use Log::Contextual::WarnLogger;
use Log::Contextual qw[ :log :dlog], -default_logger =>
  Log::Contextual::WarnLogger->new( { env_prefix => 'NET_SAML2' } );
use Net::SAML2::Exceptions;
use Err qw[ throw_err is_err ];

use namespace::autoclean;

=head1 NAME

Net::SAML2::Binding::POST - HTTP POST binding for SAML2

=head1 SYNOPSIS

  my $post = Net::SAML2::Binding::POST->new;
  my $ret = $post->handle_response(
    $saml_response
  );

=head1 METHODS

=cut

use Net::SAML2::XML::Sig;
use MIME::Base64 qw/ decode_base64 /;
use Crypt::OpenSSL::VerifyX509;
use Net::SAML2::Protocol::Assertion;
=head2 new()

Constructor. Returns an instance of the POST binding. 

No arguments.

=cut

has 'cacert' => (isa => Str, is => 'ro', required => 1);

=head2 handle_response($response)

Decodes and verifies the response provided, which should be the raw
Base64-encoded response, from the SAMLResponse CGI parameter. 

=cut

sub handle_response {
    my ($self, $response) = @_;

    # unpack and check the signature
    my $xml = decode_base64($response);
    log_debug { "handle_response, xml: $_[0]" } $xml;
    my $x = Net::SAML2::XML::Sig->new({ x509 => 1, cert => $self->cacert });
    my $ret = $x->verify($xml);
    #die "signature check failed" unless $ret;
    warn "signature check failed" unless $ret;
    Dlog_debug {"got ret from verify: $_"} $ret;
    # verify the signing certificate
    my $cert = $x->signer_cert;
    my $ca = Crypt::OpenSSL::VerifyX509->new($self->cacert);
    $ret = $ca->verify($cert);
    Dlog_debug {"got ret from \$ca->verify(\$cert) $_"} $ret;
    unless ( Net::SAML2::Protocol::Assertion->xml_is_valid_assertion($xml) ) {
        throw_err '.SAML2Error.AssertionInvalid',
          "The SAML Response received is missing an assertion.",
          meta => { xml => $xml };
    }
    my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
        xml => $xml
    );
    if ($ret) {
        return sprintf("%s (verified)", $cert->subject);
    }
    return;
}

__PACKAGE__->meta->make_immutable;
