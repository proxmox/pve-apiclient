#!/usr/bin/perl

# NOTE: you need to run this on a PVE host, or modify the source to
# provide username/password/hostname from somewhere else.

use strict;
use warnings;

use JSON;

use PVE::APIClient::LWP;

sub usage {
    print STDERR "usage: $0 <host> [<user>]\n";
    print STDERR "\n";
    print STDERR "Pass password in PMX_CLIENT_PASSWORD env. variable\n";
    print STDERR "User is either CLI argument, PMX_CLIENT_USER env. variable or 'root\@pam'\n";
    print STDERR "Pass PMX_CLIENT_FINGERPRINT env. variable for self-signed certificates.";
    exit(1);
}

my $host = shift || usage();
my $user = shift || $ENV{'PMX_CLIENT_USER'} || 'root@pam';
my $pass = $ENV{'PMX_CLIENT_PASSWORD'} || usage();

my $fps = {};

if (my $fp = $ENV{'PMX_CLIENT_FINGERPRINT'}) {
    $fps->{$fp} = 1;
}

my $conn = PVE::APIClient::LWP->new(
    username => $user,
    password => $pass,
    host => $host,
    cached_fingerprints => $fps,
);

my $res = $conn->get("api2/json/version", {});
print to_json($res, { pretty => 1, canonical => 1, utf8 => 1 });
