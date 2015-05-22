use Test::More;
use strict;
use warnings;
use FindBin;
use Net::SAML2;
use MIME::Base64;

my $xml = <<'';
<samlp:Response ID="_fc501ab5-a6a9-4a44-ac8d-33ea3350c8fe" Version="2.0" IssueInstant="2015-05-22T17:19:18.637Z" Destination="https://sso.dev.saturn.sfsrv.net/extauth/response/azure" InResponseTo="SF_b7da462a1472d80a7ee4e9751e542940" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/acb72633-aa5b-4728-893c-8566381b4d2b/</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><Assertion ID="_2500bc6d-8923-48a7-9cb3-56c643db5046" IssueInstant="2015-05-22T17:19:18.606Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>https://sts.windows.net/acb72633-aa5b-4728-893c-8566381b4d2b/</Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_2500bc6d-8923-48a7-9cb3-56c643db5046"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>L6ESkFUcXoxf+HVpojzGTB5CP7l/b5sLOHG+HoRQgD8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Tsc5M0LhX4p8fzlS3UqQd3it5PkiJ8X891he0PH0I7ofSx+2doEmyMJOlb1uxk0p8zNafODcDDV/CV6Wy2IDLsMAh6/Awq1MtnxMVuMuIaUl/M6cfEG9d0UAIP5vu6VQ7xwH8UrKl5wnuXry3Zh/OkI8Ce33YUzQi7bRrmlLSA4LAEqr1STfZCL+0GuHct8Hi8qfP+V4Zpzjtg44jQnnA7e7mZG2WAoIFKRPuowPFC9xWOaMgJEIXmLGMhqt/O/DrCayP3/gIjceqIS/Xgt/8/h2dIqdRETZveBvLWTZDVnQ1kBektHzccZ+pELBS6K1Pev3qseu3s/WZadLuNPsWQ==</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88mf3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmSBtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ==</X509Certificate></X509Data></KeyInfo></ds:Signature><Subject><NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">Dh7tdLu2gHm-Vi4emADxWxfoPB2XZvADD_H2EBlaKAw</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="SF_b7da462a1472d80a7ee4e9751e542940" NotOnOrAfter="2015-05-22T17:24:18.606Z" Recipient="https://sso.dev.saturn.sfsrv.net/extauth/response/azure"/></SubjectConfirmation></Subject><Conditions NotBefore="2015-05-22T17:14:18.606Z" NotOnOrAfter="2015-05-22T18:14:18.606Z"><AudienceRestriction><Audience>https://sso.dev.saturn.sfsrv.net</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>acb72633-aa5b-4728-893c-8566381b4d2b</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier"><AttributeValue>8081d52b-8e4a-4a8c-b8ba-ba7871eeadc0</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><AttributeValue>Kaufman</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><AttributeValue>Samuel</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/displayname"><AttributeValue>Samuel Kaufman</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>sam.kaufman.socialflow@outlook.com</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider"><AttributeValue>live.com</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="2015-05-06T14:17:15.000Z" SessionIndex="_2500bc6d-8923-48a7-9cb3-56c643db5046"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>

my $response = encode_base64($xml);

my $sp = Net::SAML2::SP->new(
        id               => 'http://localhost:3000',
        url              => 'http://localhost:3000',
        cert             => 't/sign-nopw-cert.pem',
        cacert           => "$FindBin::Bin/share/azure.idp-cacert.pem",
        org_name         => 'Test',
        org_display_name => 'Test',
        org_contact      => 'test@example.com',
);

my $post = $sp->post_binding;
my $subject = $post->handle_response($response);
ok($subject);
ok(qr/verified/, $subject);
#diag "subject: $subject\n";

my $assertion_xml = decode_base64($response);
my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
        xml => $xml,
);
ok($assertion);
#diag Dumper { assertion => $assertion };

done_testing;
