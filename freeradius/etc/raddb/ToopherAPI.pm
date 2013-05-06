package ToopherAPI;
use strict;
use Net::OAuth::ConsumerRequest;
use HTTP::Request::Common qw{ GET POST };
use JSON qw{ decode_json };
use LWP::UserAgent;
use Class::Struct;
use constant DEFAULT_TOOPHER_API => 'https://toopher-api.appspot.com/v1/';
#use constant DEFAULT_TOOPHER_API => 'https://api.toopher.com/v1/';

sub new
{
  my ($class, %args) = @_;

  if(! exists $args{'key'}){
    die("Must supply consumer key\n");
  }
  if(! exists $args{'secret'}){
    die("Must supply consumer secret\n");
  }
  my $api_url = $args{'api_url'} ? $args{'api_url'} : DEFAULT_TOOPHER_API;
  my $self = {
    _api_url => $api_url,
    _key => $args{'key'},
    _secret => $args{'secret'},
  }; 

  bless $self, $class;
  return $self;
}

sub pair
{
  my ($self, $pairing_phrase, $user_name) = @_;
  return _pairingStatusFromJson($self->post('pairings/create', 
      { 
        'pairing_phrase'=>$pairing_phrase,
        'user_name'=>$user_name,
      }));
}
sub get_pairing_status
{
  my($self, $pairing_request_id) = @_;
  return _pairingStatusFromJson($self->get('pairings/' . $pairing_request_id));
}

sub authenticate
{
  my ($self, $pairingId, $terminalName, $actionName) = @_;
  my $params = {
    'pairing_id' => $pairingId,
    'terminal_name' => $terminalName,
  };
  ${$params}{'action_name'} = $actionName if $actionName;
  return _authenticationStatusFromJson($self->post('authentication_requests/initiate', $params));
}

sub get_authentication_status
{
  my($self, $authentication_request_id) = @_;
  return _authenticationStatusFromJson($self->get('authentication_requests/' . $authentication_request_id));
}


struct(
  PairingStatus => [
    id => '$',
    pending => '$',
    enabled => '$',
    user_id => '$',
    user_name => '$',
  ]
);
struct(
  AuthenticationStatus => [
    id => '$',
    pending => '$',
    granted => '$',
    automated => '$',
    reason => '$',
    terminal_id => '$',
    terminal_name => '$',
  ]
);

sub _pairingStatusFromJson
{
  my ($jsonStr) = @_;
  my $obj = decode_json($jsonStr);
  PairingStatus->new(
    id => $obj->{'id'},
    pending => $obj->{'pending'},
    enabled => $obj->{'enabled'},
    user_id => $obj->{'user'}{'id'},
    user_name => $obj->{'user'}{'name'},
  );
}
sub _authenticationStatusFromJson
{
  my ($jsonStr) = @_;
  my $obj = decode_json($jsonStr);
  return AuthenticationStatus->new(
    id => $obj->{'id'},
    pending => $obj->{'pending'},
    granted => $obj->{'granted'},
    automated => $obj->{'automated'},
    reason => $obj->{'reason'},
    terminal_id => $obj->{'terminal'}{'id'},
    terminal_name => $obj->{'terminal'}{'name'},
  );
}

sub get
{
  my ($self, $endpoint) = @_;
  my $url = $self->{'_api_url'} . $endpoint;
  my $req = GET $url;
  return $self->request($req, {});
}
sub post
{
  my ($self, $endpoint, $params) = @_;
  my $url = $self->{'_api_url'} . $endpoint;
  my $req = POST $url, [%$params];
  return $self->request($req, $params);
}

sub request
{
  my ($self, $req,  $params) = @_;
  my $oaRequest = Net::OAuth::ConsumerRequest->new(
    consumer_key => $self->{_key},
    consumer_secret => $self->{_secret},
    request_url => $req->uri,
    request_method => $req->method,
    timestamp => time,
    nonce => substr ((rand() . ""), 2),
    signature_method => 'HMAC-SHA1',
    extra_params => $params,
  );
  $oaRequest->sign;

  $req->header('Authorization' => $oaRequest->to_authorization_header);
  my $ua = LWP::UserAgent->new;
  my $response = $ua->request($req);
  return $response->content;
}
1;
