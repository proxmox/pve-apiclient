#!/usr/bin/perl

# NOTE: you need to run this on a PVE host, or modify the source to
# provide username/password/hostname from somewhere else.

use strict;
use warnings;

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

sub get_local_cert_fingerprint {
    my ($node) = @_;
    
    my $cert_path = "/etc/pve/nodes/$node/pve-ssl.pem";
    my $custom_cert_path = "/etc/pve/nodes/$node/pveproxy-ssl.pem";

    $cert_path = $custom_cert_path if -f $custom_cert_path;

    my $bio = Net::SSLeay::BIO_new_file($cert_path, 'r');
    my $cert = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);

    my $fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    die "got empty fingerprint" if !defined($fp) || ($fp eq '');

    return $fp;
}

my $local_fingerprint = get_local_cert_fingerprint($hostname);

my $conn = PVE::APIClient::LWP->new(
    #username => 'root@pam',
    #password => 'yourpassword',
    ticket => $ticket,
    csrftoken => $csrftoken,
    host => $hostname,
    # add local hosts cert fingerprint
    cached_fingerprints => {
	$local_fingerprint => 1,
    });

my $res = $conn->get("api2/json/access/domains", {});
print to_json($res, { pretty => 1, canonical => 1});
