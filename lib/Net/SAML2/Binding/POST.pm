package Net::SAML2::Binding::POST;

use strict;
use warnings;

use Moose;
use MooseX::Types::Moose qw/ Str ArrayRef /;
use Log::Contextual::WarnLogger;
use Log::Contextual qw[ :log :dlog], -default_logger =>
  Log::Contextual::WarnLogger->new( { env_prefix => 'NET_SAML2' } );
use Net::SAML2::Exceptions;
use Err qw[ throw_err is_err ];
use Try::Tiny;

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

has cacert_list => (
    is => 'ro',
    isa => ArrayRef[Str],
    lazy => 1,
    builder => '_build_cacert_list',
);

sub _build_cacert_list {
    my( $self ) = @_;
    my $cert_path = $self->cacert;
    my @list;
    for my $p (<$cert_path*>) {
        chomp($p);
        next unless $p =~ /\Q$cert_path\E(?:\.\d+)?/;
        push @list,$p;
    }
    return \@list;
}



=head2 handle_response($response)

Decodes and verifies the response provided, which should be the raw
Base64-encoded response, from the SAMLResponse CGI parameter. 

=cut

sub handle_response {
    my ($self, $response, $p) = @_;
    $p ||= {};
    my $use_idp_cert_for_verify = $p->{use_idp_cert_for_verify};
    # unpack and check the signature
    my $xml = decode_base64($response);
    log_debug { "handle_response, xml: $_[0]" } $xml;
    if( $use_idp_cert_for_verify ) {
        my $verified = 0;
        my $error;
        my @verifiers = map {
            Net::SAML2::XML::Sig->new({ x509 => 1, cert => $_ });
        } @{ $self->cacert_list };
        for my $verifier ( @verifiers ) {
            try {
                my $ret = $verifier->verify($xml);
                $verified = 1 if $ret;
            } catch {
                $error = $_;
                log_warn { "got error: $error verifying cert"} $error;
            };
        }
        unless( $verified )  {
            confess "signature check failed" unless $verified;
        }
    }
    my $x = Net::SAML2::XML::Sig->new({ x509 => 1 });
    my $ret = $x->verify($xml);
    confess "signature check failed" unless $ret;
    Dlog_debug {"got ret from verify: $_"} $ret;
    # verify the signing certificate
    my $cert = $x->signer_cert;
    my @_x509 = map {
        Crypt::OpenSSL::X509->new_from_file($self->cacert);
    } @{ $self->cacert_list };
    for my $x509 (@_x509) {
        my $contraints;
        try {
            $contraints = $x509->extensions->{'X509v3 Basic Constraints'};
        }
        catch {
            warn "error getting constraints, $_";
        };
        if ( $contraints && $contraints->to_string =~ /CA:FALSE/ ) {
            log_debug {
"cert is explicitly not a CA cert, unable to verify the message. "
            }
            return sprintf( "%s (verified)", $cert->subject );
        }
    }
    my @cas = map {
        Crypt::OpenSSL::VerifyX509->new( $_ )
    }   @{ $self->cacert_list };
    my($verify_ret,$error);
    my $verified = 0;
    for my $ca (@cas) {
        try {
            $verify_ret = $ca->verify($cert);
            if( $verify_ret ) {
                $verified = 1;
            }
        }
        catch {
            $error = $_;
            log_warn { "couldnt verify with cert, $_" } $error;
        };
    }
    unless( $verified ) {
        confess $error unless $verified;
    }
    Dlog_debug {"got ret from \$ca->verify(\$cert) $_"} $verify_ret;
    unless ( Net::SAML2::Protocol::Assertion->xml_is_valid_assertion($xml) ) {
        throw_err '.SAML2Error.AssertionInvalid',
          "The SAML Response received is missing an assertion.",
          meta => { xml => $xml };
    }
    my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
        xml => $xml
    );
    if ($verify_ret) {
        return sprintf("%s (verified)", $cert->subject);
    }
    return;
}

__PACKAGE__->meta->make_immutable;
