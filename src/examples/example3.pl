#!/usr/bin/perl

# NOTE: you need to set the API token and PVE host below for this to work

use strict;
use warnings;

use PVE::APIClient::LWP;

use JSON;

my $apitoken = 'PVEAPIToken=USER@REALM!TOKENID=TOKENVALUE';
my $hostname = "127.0.0.1";

my $conn = PVE::APIClient::LWP->new(
    apitoken => $apitoken,
    host => $hostname,
    # allow manual fingerprint verification
    manual_verification => 1,
);

my $res = $conn->get("/access/permissions", {});

print to_json($res, { pretty => 1, canonical => 1 });
