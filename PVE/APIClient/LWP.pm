package PVE::APIClient::LWP;

use strict;
use warnings;

use Carp;
use HTTP::Request::Common;
use IO::Socket::SSL; # important for SSL_verify_callback
use JSON;
use LWP::UserAgent;
use Net::SSLeay;
use URI::Escape;
use URI;

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

sub two_factor_auth_login {
    my ($self, $type, $challenge) = @_;

    if ($type eq 'PVE:tfa') {
	raise("TFA-enabled login currently works only with a TTY.") if !-t STDIN;
	print "\nEnter OTP code for user $self->{username}: ";
	my $tfa_response = <STDIN>;
	chomp $tfa_response;
	return $self->post('/api2/json/access/tfa', {response => $tfa_response});
    } elsif ($type eq 'PVE:u2f') {
	# TODO: implement u2f-enabled join
	raise("U2F-enabled login is currently not implemented.");
    } else {
	raise("Authentication type '$type' not recognized, aborting!");
    }
}

sub login {
    my ($self) = @_;

    my $uri = URI->new();
    $uri->scheme($self->{protocol});
    $uri->host($self->{host});
    $uri->port($self->{port});
    $uri->path('/api2/json/access/ticket');

    my $ua = $self->{useragent};
    my $username = $self->{username} // 'unknown',

    delete $self->{fingerprint}->{last_unknown};

    my $exec_login = sub {
	return $ua->post($uri, {
	    username => $username,
	    password => $self->{password} || ''
	});
    };

    my $response = $exec_login->();

    if (!$response->is_success) {
	if (my $fp = delete($self->{fingerprint}->{last_unknown})) {
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

    # handle two-factor login
    my $tfa_ticket_re = qr/^([^\s!]+)![^!]*(!([0-9a-zA-Z\/.=_\-+]+))?$/;
    if ($data->{ticket} =~ m/$tfa_ticket_re/) {
	my ($type, $challenge) = ($1, $2);
	$data = $self->two_factor_auth_login($type, $challenge);
	$self->update_ticket($data->{ticket});
    }

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

    $self->{fingerprint}->{cache}->{$fingerprint} = $valid;

    raise("Fingerprint not verified, abort!\n") if !$valid;

    if (my $cb = $self->{register_fingerprint_cb}) {
	$cb->($fingerprint) if $valid;
    }

    return $valid;
}

sub call {
    my ($self, $method, $path, $param) = @_;

    delete $self->{fingerprint}->{last_unknown};

    my $ticket = $self->{ticket};
    my $apitoken = $self->{apitoken};

    my $ua = $self->{useragent};

    # fixme: check ticket lifetime?

    if (!$ticket && !$apitoken && $self->{username} && $self->{password}) {
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

    if (my $fp = delete($self->{fingerprint}->{last_unknown})) {
	if ($self->manual_verify_fingerprint($fp)) {
	    $response = $exec_method->(); # try again
	}
    }

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

my sub verify_cert_callback {
    my ($fingerprint, $cert, $verify_cb) = @_;

    # check server certificate against cache of pinned FPs
    # get fingerprint of server certificate
    my $fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    return 0 if !defined($fp) || $fp eq ''; # error

    my $valid = $fingerprint->{cache}->{$fp};
    return $valid if defined($valid); # return cached result

    if ($verify_cb) {
	$valid = $verify_cb->($cert);
	$fingerprint->{cache}->{$fp} = $valid;
	return $valid;
    }

    $fingerprint->{last_unknown} = $fp;

    return 0;
};

sub new {
    my ($class, %param) = @_;

    my $ssl_opts = $param{ssl_opts} || {};

    if (!defined($ssl_opts->{verify_hostname})) {
	if (scalar(keys $param{cached_fingerprints}->%*) > 0) {
	    # purely trust the configured fingerprints, by default
	    $ssl_opts->{verify_hostname} = 0;
	} else {
	    # no fingerprints passed, enforce hostname verification, by default
	    $ssl_opts->{verify_hostname} = 1;
	}
    }
    # we can only really trust openssl result if it also verifies the hostname,
    # else it's easy to intercept (MITM using valid Lets Encrypt)
    my $trust_openssl = $ssl_opts->{verify_hostname} ? 1 : 0;

    my $self = {
	username => $param{username},
	password => $param{password},
	host => $param{host} || 'localhost',
	port => $param{port},
	protocol => $param{protocol},
	cookie_name => $param{cookie_name} // 'PVEAuthCookie',
	manual_verification => $param{manual_verification},
	fingerprint => {
	    cache => $param{cached_fingerprints} || {},
	    last_unknown => undef,
	},
	register_fingerprint_cb => $param{register_fingerprint_cb},
	timeout => $param{timeout} || 60,
    };
    bless $self, $class;

    if (!$ssl_opts->{SSL_verify_callback}) {
	$ssl_opts->{'SSL_verify_mode'} = SSL_VERIFY_PEER;

	my $fingerprints = $self->{fingerprint}; # avoid passing $self, that's a RC cycle!
	my $verify_fingerprint_cb = $param{verify_fingerprint_cb};
	$ssl_opts->{'SSL_verify_callback'} = sub {
	    my ($openssl_valid, undef, undef, undef, $cert, $depth) = @_;

	    # we don't care about intermediate or root certificates
	    return 1 if $depth != 0;

	    return 1 if $trust_openssl && $openssl_valid;

	    return verify_cert_callback($fingerprints, $cert, $verify_fingerprint_cb);
	}
    }

    if (!$self->{port}) {
	$self->{port} = $self->{host} eq 'localhost' ? 85 : 8006;
    }
    if (!$self->{protocol}) {
	# cope that PBS and PVE can be installed on the same host, and one may thus use
	# 'localhost' then - so only default to http for privileged ports, in that case,
	# as the HTTP daemons normally run with those (e.g., 85 or 87)
	$self->{protocol} = $self->{host} eq 'localhost' && $self->{port} < 1024
	    ? 'http'
	    : 'https'
	    ;
    }

    $self->{useragent} = LWP::UserAgent->new(
	protocols_allowed => [ 'http', 'https'],
	ssl_opts => $ssl_opts,
	timeout => $self->{timeout},
	keep_alive => $param{keep_alive} // 50,
	);

    $self->{useragent}->default_header('Accept-Encoding' => 'gzip'); # allow gzip

    if ($param{apitoken} && $param{password}) {
	warn "password will be ignored in favor of API token\n";
	delete $self->{password};
    }
    if ($param{ticket}) {
	if ($param{apitoken}) {
	    warn "ticket will be ignored in favor of API token\n";
	} else {
	    $self->update_ticket($param{ticket});
	}
    }
    $self->update_csrftoken($param{csrftoken}) if $param{csrftoken};

    if ($param{apitoken}) {
	my $agent = $self->{useragent};

	$self->{apitoken} = $param{apitoken};

	$agent->default_header('Authorization', $param{apitoken});
    }

    return $self;
}

1;
