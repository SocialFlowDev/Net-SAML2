package Net::SAML2::Protocol::Assertion;
use Moose;
use MooseX::Types::Moose qw/ Str HashRef ArrayRef /;
use MooseX::Types::DateTime qw/ DateTime /;
use MooseX::Types::Common::String qw/ NonEmptySimpleStr /;
use DateTime;
use DateTime::Format::XSD;
use Carp;
use XML::XPath;
use namespace::autoclean;

with 'Net::SAML2::Role::ProtocolMessage';

=head1 NAME

Net::SAML2::Protocol::Assertion - SAML2 assertion object

=head1 SYNOPSIS

  my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
    xml => decode_base64($SAMLResponse)
  );

=cut

has 'attributes' => ( isa => HashRef [ArrayRef], is => 'ro', required => 1 );
has 'session'       => ( isa => Str,               is => 'ro', required => 1 );
has 'nameid'        => ( isa => Str,               is => 'ro', required => 1 );
has 'not_before'    => ( isa => DateTime,          is => 'ro', required => 1 );
has 'not_after'     => ( isa => DateTime,          is => 'ro', required => 1 );
has 'issue_instant' => ( isa => DateTime,          is => 'ro', required => 0 );
has 'audience'      => ( isa => NonEmptySimpleStr, is => 'ro', required => 1 );

=head1 METHODS

=cut

=head2 new_from_xml( ... )

Constructor. Creates an instance of the Assertion object, parsing the
given XML to find the attributes, session and nameid. 

=cut

sub xml_is_valid_assertion {
    my ( $class, $xml ) = @_;
    my $xpath = XML::XPath->new( xml => $xml );
    $xpath->set_namespace( 'saml', 'urn:oasis:names:tc:SAML:2.0:assertion' );
    unless ( $xpath->findnodes('//saml:Assertion') ) {
        return 0;
    }
    return 1;
}
sub new_from_xml {
    my ( $class, %args ) = @_;

    my $xpath = XML::XPath->new( xml => $args{xml} );
    $xpath->set_namespace( 'saml', 'urn:oasis:names:tc:SAML:2.0:assertion' );
    unless ( $class->xml_is_valid_assertion( $args{xml} ) ) {
        confess
"xml is not a valid assertion, please check xml_is_valid_assertion(\$xml) first.";
    }
    my $attributes = {};
    for my $node (
        $xpath->findnodes(
            '//saml:Assertion/saml:AttributeStatement/saml:Attribute') )
    {
        my @values = $node->findnodes('saml:AttributeValue|AttributeValue');
        $attributes->{ $node->getAttribute('Name') } =
          [ map { $_->string_value } @values ];
    }

    my $not_before = DateTime::Format::XSD->parse_datetime(
        $xpath->findvalue('//saml:Conditions/@NotBefore')->value );
    my $not_after = DateTime::Format::XSD->parse_datetime(
        $xpath->findvalue('//saml:Conditions/@NotOnOrAfter')->value );
    my $issue_instant = DateTime::Format::XSD->parse_datetime(
        $xpath->findvalue('//saml:Assertion/@IssueInstant')->value );
    my $self = $class->new(
        attributes => $attributes,
        session =>
          $xpath->findvalue('//saml:AuthnStatement/@SessionIndex')->value,
        nameid   => $xpath->findvalue('//saml:Subject/saml:NameID')->value,
        audience => $xpath->findvalue(
            '//saml:Conditions/saml:AudienceRestriction/saml:Audience')->value,
        not_before => $not_before,
        not_after  => $not_after,
        issue_instant => $issue_instant
    );

    return $self;
}

=head2 name

Returns the CN attribute, if provided.

=cut

sub name {
    my ($self) = @_;
    return $self->attributes->{CN}->[0];
}

=head2 valid( $audience, %opt )

Returns true if this Assertion is currently valid for the given audience.

Checks the audience matches, and that the current time is within the
Assertions validity period as specified in its Conditions element.

C<%opt> can contain C<no_audience> as a true value to exclude audience
checks.

=cut

sub valid {
    my ($self, $audience, %opt) = @_;

    unless ($opt{no_audience} || !$self->audience) {
        return 0 unless defined $audience;
        return 0 unless ($audience eq $self->audience);
    }

    my $now = DateTime::->now;
    #check if the current time is less than NotBefore time
    if (DateTime::->compare($now, $self->not_before) == -1) {
        #check if IssueInstant exists
        #check if current time is less than IssueInstant time
        #check if the difference between IssueInstant time and current time is less than 5 minutes 
        if ($self->issue_instant) {
            my $issue_instant = $self->issue_instant;
            my $diff = $issue_instant->subtract_datetime($now);
            if ( DateTime::->compare($now, $self->issue_instant) == -1 && $diff->minutes() < 6) {
                #set the current time to be the IssueInstant time
                $now = $self->issue_instant;
            } else {
                warn 'Difference between IssueInstant and current time is greater than 6 minutes';
            }
        } else {
            warn 'IssueInstant time not found';
        }
    }
        
    # not_before is "NotBefore" element - exact match is ok
    # not_after is "NotOnOrAfter" element - exact match is *not* ok
    return 0 unless DateTime::->compare($now, $self->not_before) > -1;
    return 0 unless DateTime::->compare($self->not_after, $now) > 0;

    return 1;
}

__PACKAGE__->meta->make_immutable;
1;
