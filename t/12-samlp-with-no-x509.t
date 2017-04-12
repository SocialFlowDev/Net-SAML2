use strict;
use warnings FATAL => 'all';

use Test::More;
use IO::All;
use FindBin;
use MIME::Base64 qw/ decode_base64 encode_base64/;
use Data::Dumper::Concise;
use Try::Tiny;

plan tests => 4;

use lib "$FindBin::Bin/../lib";

use Net::SAML2::Binding::POST;

my $cacert = io->catfile( "$FindBin::Bin", "share", "net-samlp-no-x509-key.idp-cacert.pem" )->name;
my $post = Net::SAML2::Binding::POST->new( cacert => $cacert );

diag Dumper $post->cacert_list;

is 0+@{$post->cacert_list},1,"one cert in list";
is $post->cacert_list->[0],$post->cacert,"first one in the list is the passed filename";


my $xml = io->catfile( $FindBin::Bin, "share", "net-samlp-no-x509-key.xml" )->slurp;

try {
 $post->handle_response( encode_base64( $xml ),{ use_idp_cert_for_verify => 1 });
 ok 1,"handle_response did not die";
} catch {
    diag $_;
    fail "handle_response should not die";
};

my $res =  $post->handle_response( encode_base64( $xml ),{ use_idp_cert_for_verify => 1 });

my $bad_xml = io->catfile( $FindBin::Bin, "share", "net-samlp-no-x509-key-bad-assertion.xml" )->slurp;

try {
    $res = $post->handle_response( encode_base64( $bad_xml ),{ use_idp_cert_for_verify => 1 });
    fail "Should not validate bad xml";
} catch {
    ok $_,"verify failed correctly with bad assertion";
};

diag Dumper $res;
