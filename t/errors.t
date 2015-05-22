use strict;
use warnings;

use Test::More;
use Net::SAML2;

plan tests => 1;

my $xml = <<XML;
<samlp:Response Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" Destination="https://sso.dev.saturn.sfsrv.net/extauth/response/ssodev1" ID="_2e749c33-e90c-4526-9773-2a1e3f9cfc2c" InResponseTo="SF_d817297f35c9adb266b9fcf08b5ca54b" IssueInstant="2015-05-14T15:52:35.434Z" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">http://sso-01.socialflow.local/adfs/services/trust</Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_2e749c33-e90c-4526-9773-2a1e3f9cfc2c">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>0Dq2BZWxu+i32dDdIdsUXYKkUVmruR+btA9s1l0Mc2g=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>kJ2T+zdF8waw7h+4Yo6W1lrlF0Vdj7dvKcWwjqTLNvnnBpBJm5txHpeWaI2n920BGL89Gb/SfintC1D2OgOfuLd/JhN1u12srzAXnHrkgHtDgRQKb4+9x4LmJ6meZVVcbuBxdfJOvzhxJaRD/BFgaSVEWihtG0O9rECz9tIf9FZz25fsorTY4v9YQAtuhoRXKIlJoKBJW5sCdX1ORHRyDbBO2dMng54IAw4OXYMqv487YM40jZgoISnjPzz4Yu6ODcb2KoloO7NUm2SoVTAhvanRK/524lgsnwvv0pSrbqwcAHVCFaBhXYmaM36T2EE+yYtD7K6kgECZ0pHyoet7Nw==</ds:SignatureValue>
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
      <ds:X509Data>
        <ds:X509Certificate>MIIDCjCCAfKgAwIBAgIQOkc1dAE5VLpJKONv0XEW6DANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZBREZTIFNpZ25pbmcgLSBXSU4tNUNNUjZHODdFVjkuc3NvLTAxLnNvY2lhbGZsb3cubG9jYWwwHhcNMTUwNTEyMjEyMjU1WhcNMTYwNTExMjEyMjU1WjBBMT8wPQYDVQQDEzZBREZTIFNpZ25pbmcgLSBXSU4tNUNNUjZHODdFVjkuc3NvLTAxLnNvY2lhbGZsb3cubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCWCsVP8QcBeUxTqmaoJuNBaFyi3PDSqBSSuDLFW8idyZnaj/sTHcVSudhVWGItzKY60ZRcNq0qF2PidpugdVYZwQZ7Wvsf7Q1X7atvWXWVWWYnfN8pFWxXiPpCZwJaUJGJSkd/UySGnWBGte66v4zXzS1270MxOze7mpu//JnLi9xL1SS9QTNhCg4tSS69+LditACIx2QGZ/Lrmtgvwk2aGJzZS52EZ1CL0A9pwgpyVZHsKQTGDx6nshmsdG36Hq5REyMk6Wh7ihtiX6/ahzTXPXNtqGCDgN5qfbWM08btwKPTUzRmWbNUOdL/4iMmzAi/zyw7nIzrXBTsSc5zRRjnAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAD0M+bWtoQccsQ/ipTjKtBKpx28Q6VVJMcyPCfhBj2loWJ5jJJQe/LTipqy7OTqzjfR6SC8um9pGtnXwp5a3EsNHXhbYVmDwvXZjp2F25FN5Zy/8PY+vlmbkBZ4foAJWz5se/5Sd4q6FyG7G8y8dQJsA5GpacC/zXj0PP57p15xEb8YJE7B2IvnOsdzbra23MgUBC7LfmEujO1m+TCq9yS/YcDiGkFWfaTni4+jAP4aQ79zsneJtD+UbyO7OOg95/nXvd7SR9XO7urL6IVsYuovkvt1Tgi3GHXLd6enDLg2fb8CeHQ+JEciDTfKWijbUAGV5Tis4XFx+u7dAJJQ04zE=</ds:X509Certificate>
      </ds:X509Data>
    </KeyInfo>
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>
  </samlp:Status>
</samlp:Response>
XML

ok !Net::SAML2::Protocol::Assertion->xml_is_valid_assertion($xml),
  "assertion is not valid.";
