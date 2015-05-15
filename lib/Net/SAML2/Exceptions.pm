use strict;
use warnings;

package Net::SAML2::Exceptions;

use Err qw[ declare_err throw_err is_err ];

declare_err ".SAML2Error", meta => undef;

declare_err ".SAML2Error.AssertionInvalid",
  description          => "The SAML Response received has a missing or invalid SAML Assertion.";

1;
