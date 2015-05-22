use strictures 2;

use Test::More;

plan tests => 1;
use Net::SAML2::Binding::POST;
use Net::SAML2::XML::Sig;

use FindBin;
use IO::All;
use MIME::Base64 qw/ decode_base64 encode_base64 /;

my $cacert = io->catfile( "$FindBin::Bin", "share", "ssodev1.idp-cacert.pem" )->name;
my $post = Net::SAML2::Binding::POST->new( cacert => $cacert );
my $xml = io->catfile( $FindBin::Bin, "share", "samlp_assertion-01.xml" )->slurp;
my $x = Net::SAML2::XML::Sig->new({ x509 => 1, cert => $cacert });
my $ret = $x->verify($xml);
warn $ret;
ok $post->handle_response( encode_base64( $xml ) );
