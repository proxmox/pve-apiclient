#!/usr/bin/perl

use strict;
use warnings;

# NOTE: you need to run this on a PVE host, or modify the source to
# provide username/password/hostname from somewhere else.

use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );

use PVE::APIClient::LWP;
use PVE::AccessControl;
use PVE::INotify;
use JSON;

# normally you use username/password,
# but we can simply create a ticket and CRSF token if we are root
# running on a pve host

my $hostname = PVE::INotify::read_file("hostname");
my $ticket = PVE::AccessControl::assemble_ticket('root@pam');
my $csrftoken = PVE::AccessControl::assemble_csrf_prevention_token('root@pam');

my $wcount = 10;
my $qcount = 100;

sub get_local_cert_fingerprint { my ($node) = @_; my $cert_path =
    "/etc/pve/nodes/$node/pve-ssl.pem"; my $custom_cert_path =
    "/etc/pve/nodes/$node/pveproxy-ssl.pem";

    $cert_path = $custom_cert_path if -f $custom_cert_path;

    my $bio = Net::SSLeay::BIO_new_file($cert_path, 'r'); my $cert =
    Net::SSLeay::PEM_read_bio_X509($bio); Net::SSLeay::BIO_free($bio);

    my $fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256'); die
    "got empty fingerprint" if !defined($fp) || ($fp eq '');

    return $fp; }

my $local_fingerprint = get_local_cert_fingerprint($hostname);

sub test_rpc {
    my ($host) = @_;

    my $conn = PVE::APIClient::LWP->new(
	#username => 'root@pam',
	#password => 'yourpassword',
	ticket => $ticket,
	csrftoken => $csrftoken,
	host => $host,
	# add local hosts cert fingerprint
	cached_fingerprints => {
	    $local_fingerprint => 1,
    });

    for (my $i = 0; $i < $qcount; $i++) {
	eval {
	    my $res = $conn->get("/", {});
	};
	if (my $err = $@) {
	    print "ERROR: $err\n";
	    last;
	}
    }
}

sub run_tests {
    my ($host) = @_;
    
    my $workers;

    my $starttime = [gettimeofday];

    for (my $i = 0; $i < $wcount; $i++) {
	if (my $pid = fork ()) {
	    $workers->{$pid} = 1;
	} else {
	    test_rpc($host);
	    exit (0);
	}
    }

    # wait for children
    1 while (wait > 0);

    my $elapsed = int(tv_interval ($starttime) * 1000);

    my $tpq = $elapsed / ($wcount*$qcount);

    print "$host: $tpq ms per query\n";
}

run_tests("localhost"); # test 'pvedaemon'

run_tests($hostname); # test 'pveproxy'
