package PVE::APIClient::LWP;

use strict;
use warnings;
use URI;
use IO::Socket::SSL; # important for SSL_verify_callback
use LWP::UserAgent;
use URI::Escape;
use Net::SSLeay;
use JSON;
use Data::Dumper; # fixme: remove
use HTTP::Request::Common;
use Carp;
use PVE::APIClient::Exception qw(raise);

my $extract_data = sub {
    my ($res) = @_;

    croak "undefined result" if !defined($res);
    croak "undefined result data" if !exists($res->{data});

    return $res->{data};
};

sub get_raw {
    my ($self, $path, $param) = @_;

    return $self->call('GET', $path, $param);
}

sub get {
    my ($self, $path, $param) = @_;

    return $extract_data->($self->call('GET', $path, $param));
}

sub post_raw {
    my ($self, $path, $param) = @_;

    return $self->call('POST', $path, $param);
}

sub post {
    my ($self, $path, $param) = @_;

    return $extract_data->($self->call('POST', $path, $param));
}

sub put_raw {
    my ($self, $path, $param) = @_;

    return $self->call('PUT', $path, $param);
}

sub put {
    my ($self, $path, $param) = @_;

    return $extract_data->($self->call('PUT', $path, $param));
}

sub delete_raw {
    my ($self, $path, $param) = @_;

    return $self->call('DELETE', $path, $param);
}

sub delete {
    my ($self, $path, $param) = @_;

    return $extract_data->($self->call('DELETE', $path, $param));
}

sub update_csrftoken {
    my ($self, $csrftoken) = @_;

    $self->{csrftoken} = $csrftoken;

    my $agent = $self->{useragent};

    $agent->default_header('CSRFPreventionToken', $self->{csrftoken});
}

sub update_ticket {
    my ($self, $ticket) = @_;

    my $agent = $self->{useragent};

    $self->{ticket} = $ticket;

    my $encticket = uri_escape($ticket);
    my $cookie = "$self->{cookie_name}=$encticket; path=/; secure;";
    $agent->default_header('Cookie', $cookie);
}

sub login {
    my ($self) = @_;

    my $uri = URI->new();
    $uri->scheme($self->{protocol});
    $uri->host($self->{host});
    $uri->port($self->{port});
    $uri->path('/api2/json/access/ticket');

    my $ua = $self->{useragent};

    delete $self->{last_unknown_fingerprint};

    my $exec_login = sub {
	return $ua->post($uri, {
	    username => $self->{username} || 'unknown',
	    password => $self->{password} || ''});
    };

    my $response = $exec_login->();

    if (!$response->is_success) {
	if (my $fp = delete($self->{last_unknown_fingerprint})) {
	    if ($self->manual_verify_fingerprint($fp)) {
		$response = $exec_login->(); # try again
	    }
	}
    }

    if (!$response->is_success) {
	raise($response->status_line ."\n", code => $response->code)
    }

    my $res = from_json($response->decoded_content, {utf8 => 1, allow_nonref => 1});

    my $data = $extract_data->($res);

    $self->update_ticket($data->{ticket});
    $self->update_csrftoken($data->{CSRFPreventionToken});

    return $data;
}

sub manual_verify_fingerprint {
    my ($self, $fingerprint) = @_;

    if (!$self->{manual_verification}) {
	raise("fingerprint '$fingerprint' not verified, abort!\n");
    }

    print "The authenticity of host '$self->{host}' can't be established.\n" .
	"X509 SHA256 key fingerprint is $fingerprint.\n" .
	"Are you sure you want to continue connecting (yes/no)? ";

    my $answer = <STDIN>;

    my $valid = ($answer =~ m/^\s*yes\s*$/i) ? 1 : 0;

    $self->{cached_fingerprints}->{$fingerprint} = $valid;

    raise("Fingerprint not verified, abort!\n") if !$valid;

    if (my $cb = $self->{register_fingerprint_cb}) {
	$cb->($fingerprint) if $valid;
    }

    return $valid;
}

sub call {
    my ($self, $method, $path, $param) = @_;

    delete $self->{last_unknown_fingerprint};

    my $ticket = $self->{ticket};

    my $ua = $self->{useragent};

    # fixme: check ticket lifetime?

    if (!$ticket && $self->{username} && $self->{password}) {
	$self->login();
    }

    my $uri = URI->new();
    $uri->scheme($self->{protocol});
    $uri->host($self->{host});
    $uri->port($self->{port});

    $path =~ s!^/+!!;

    if ($path !~ m!^api2/!) {
	$uri->path("api2/json/$path");
    } else {
	$uri->path($path);
    }

    #print "CALL $method : " .  $uri->as_string() . "\n";

    my $exec_method = sub {

	my $response;
	if ($method eq 'GET') {
	    $uri->query_form($param);
	    $response = $ua->request(HTTP::Request::Common::GET($uri));
	} elsif ($method eq 'POST') {
	    $response = $ua->request(HTTP::Request::Common::POST($uri, Content => $param));
	} elsif ($method eq 'PUT') {
	    # We use another temporary URI object to format
	    # the application/x-www-form-urlencoded content.

	    my $tmpurl = URI->new('http:');
	    $tmpurl->query_form(%$param);
	    my $content = $tmpurl->query;

	    $response = $ua->request(HTTP::Request::Common::PUT($uri, 'Content-Type' => 'application/x-www-form-urlencoded', Content => $content));

	} elsif ($method eq 'DELETE') {
	    $response = $ua->request(HTTP::Request::Common::DELETE($uri));
	} else {
	    raise("method $method not implemented\n");
	}
	return $response;
    };

    my $response = $exec_method->();

    if (my $fp = delete($self->{last_unknown_fingerprint})) {
	if ($self->manual_verify_fingerprint($fp)) {
	    $response = $exec_method->(); # try again
	}
    }

    #print "RESP: " . Dumper($response) . "\n";

    my $ct = $response->header('Content-Type') || '';

    if ($response->is_success) {

	raise("got unexpected content type", code => $response->code)
	    if $ct !~ m|application/json|;

	return from_json($response->decoded_content, {utf8 => 1, allow_nonref => 1});

    } else {

	my $msg = $response->message;
	my $errors = eval {
	    return if $ct !~ m|application/json|;
	    my $res = from_json($response->decoded_content, {utf8 => 1, allow_nonref => 1});
	    return $res->{errors};
	};

	raise("$msg\n", code => $response->code, errors => $errors);
    }
}

my $verify_cert_callback = sub {
    my ($self, $cert) = @_;

    # check server certificate against cache of pinned FPs
    # get fingerprint of server certificate
    my $fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    return 0 if !defined($fp) || $fp eq ''; # error

    my $valid = $self->{cached_fingerprints}->{$fp};
    return $valid if defined($valid); # return cached result

    if (my $cb = $self->{verify_fingerprint_cb}) {
	$valid = $cb->($cert);
	$self->{cached_fingerprints}->{$fp} = $valid;
	return $valid;
    }

    $self->{last_unknown_fingerprint} = $fp;

    return 0;
};

sub new {
    my ($class, %param) = @_;

    my $ssl_default_opts = { verify_hostname => 0 };
    my $ssl_opts = $param{ssl_opts} || $ssl_default_opts;

    my $self = {
	username => $param{username},
	password => $param{password},
	host => $param{host} || 'localhost',
	port => $param{port},
	protocol => $param{protocol},
	cookie_name => $param{cookie_name} // 'PVEAuthCookie',
	manual_verification => $param{manual_verification},
	cached_fingerprints => $param{cached_fingerprints} || {},
	verify_fingerprint_cb => $param{verify_fingerprint_cb},
	register_fingerprint_cb => $param{register_fingerprint_cb},
	ssl_opts => $ssl_opts,
	timeout => $param{timeout} || 60,
    };
    bless $self;

    if (!$ssl_opts->{SSL_verify_callback}) {
	$ssl_opts->{'SSL_verify_mode'} = SSL_VERIFY_PEER;
	$ssl_opts->{'SSL_verify_callback'} = sub {
	    my (undef, undef, undef, undef, $cert, $depth) = @_;

	    # we don't care about intermediate or root certificates
	    return 1 if $depth != 0;

	    return $verify_cert_callback->($self, $cert);
	}
    }

    if (!$self->{port}) {
	$self->{port} = $self->{host} eq 'localhost' ? 85 : 8006;
    }
    if (!$self->{protocol}) {
	$self->{protocol} = $self->{host} eq 'localhost' ? 'http' : 'https';
    }

    $self->{useragent} = LWP::UserAgent->new(
	protocols_allowed => [ 'http', 'https'],
	ssl_opts => $ssl_opts,
	timeout => $self->{timeout},
	keep_alive => $param{keep_alive} // 50,
	);

    $self->{useragent}->default_header('Accept-Encoding' => 'gzip'); # allow gzip

    $self->update_ticket($param{ticket}) if $param{ticket};
    $self->update_csrftoken($param{csrftoken}) if $param{csrftoken};


    return $self;
}

1;
