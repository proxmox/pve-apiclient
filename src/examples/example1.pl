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

my $conn = PVE::APIClient::LWP->new(
    #username => 'root@pam',
    #password => 'yourpassword',
    ticket => $ticket,
    csrftoken => $csrftoken,
    host => $hostname,
    # allow manual fingerprint verification
    manual_verification => 1,
    );

my $res = $conn->get("/", {});

print to_json($res, { pretty => 1, canonical => 1});
