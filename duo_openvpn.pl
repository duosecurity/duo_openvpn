#!/usr/bin/env perl

use strict;
use warnings;
use LWP::UserAgent;
use Sys::Syslog qw(:standard);
use URI::Escape;
use MIME::Base64;
use JSON::XS;
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);
use Data::Dumper;
use File::Spec;
$Data::Dumper::Indent = 0;
$Data::Dumper::Terse  = 1;

my $API_RESULT_AUTH   = qr/^auth$/;
my $API_RESULT_ALLOW  = qr/^allow$/;
my $API_RESULT_DENY   = qr/^deny$/;
my $API_RESULT_ENROLL = qr/^enroll$/;

openlog 'duo_openvpn.pl', 'pid', 'LOG_AUTH';

my $control  = $ENV{'control'};
my $username = $ENV{'username'};
my $password = $ENV{'password'};
my $ipaddr   = $ENV{'ipaddr'} || '0.0.0.0';

if (not $control or not $username or not $password) {
    logger('required environmental variables not found');
    exit 1;
}

my $ikey = $ENV{'ikey'};
my $skey = $ENV{'skey'};
my $host = $ENV{'host'};

if (not $ikey or not $skey or not $host) {
    logger('required ikey/skey/host configuration');
    failure();
}

my $ca_certs = get_ca_certs();

preauth();
auth();
failure();

sub get_ca_certs {
    my $abspath = File::Spec->rel2abs(__FILE__);
    my ($volume, $directories, $file) = File::Spec->splitpath($abspath);

    return File::Spec->catpath($volume, $directories, 'ca_certs.pem');
}

sub canonicalize {
    my $host   = shift;
    my $uri    = shift;
    my $params = shift;

    my @args  = ();

    foreach my $key (sort (keys %{$params})) {
        push @args, (uri_escape($key) . '=' . uri_escape($params->{$key}));
    }

    my @canon = ('POST', lc $host, $uri, (join '&', @args));

    return join "\n", @canon;
}


sub sign {
    my ($ikey, $skey, $host, $path, $args) = @_;

    my $sig = hmac_sha1_hex(canonicalize($host, $path, $args), $skey);
    my $auth = "$ikey:$sig";
    return 'Basic ' . encode_base64($auth, '');
}


sub call {
    my ($ikey, $skey, $host, $path, $kwargs) = @_;

    my $ssl_opts = {
        verify_hostname => 1,
        SSL_ca_file => $ca_certs,
        SSL_ca_path => undef
    };

    my $ua = LWP::UserAgent->new(ssl_opts => $ssl_opts);

    $ua->default_header(
        'Authorization' => sign($ikey, $skey, $host, $path, $kwargs),
    );

    my $response = $ua->post('https://' . $host . $path, $kwargs);
    my $data = '{}';

    if ($response->is_success) {
        $data = $response->content;
    }

    return ($response->code, $response->message, $data);
}


sub api {
    my ($ikey, $skey, $host, $path, $args) = @_;

    my ($status, $reason, $json) = call($ikey, $skey, $host, $path, $args);

    if ($status != 200) {
        logger("Received $status $reason: $json");
        failure();
    }

    my $data = decode_json $json;

    if (defined $data->{stat} and $data->{stat} !~ /^OK$/o) {
        logger("Received error response: $json");
        failure();
    }

    if (not defined $data->{'response'}) {
        logger("Received bad response: $json");
        failure();
    }

    if (not defined $data->{'response'}{'result'}) {
        logger("invalid API response: " . $data->{'response'});
        failure();
    }

    return $data->{'response'};
}


sub auth {
    logger("authentication for $username");

    my $args = {
        'user'   => $username,
        'factor' => 'auto',
        'auto'   => $password,
        'ipaddr' => $ipaddr,
    };

    my $response = api($ikey, $skey, $host, '/rest/v1/auth', $args);

    my $result = $response->{'result'};
    my $status = $response->{'status'};

    if (not defined $status) {
        logger("invalid API response: $response");
        failure();
    }

    if ($result =~ $API_RESULT_ALLOW) {
        logger("auth success for $username: $status");
        success();
    }
    elsif ($result =~ $API_RESULT_DENY) {
        logger("auth failure for $username: $status");
        failure();
    }
    else {
        logger("unknown auth result: $result");
        failure();
    }
}


sub preauth {
    logger("pre-authentication for $username");

    my $args = {
        user => $username,
    };

    my $response = api($ikey, $skey, $host, '/rest/v1/preauth', $args);

    my $result = $response->{'result'};
    my $status = $response->{'status'};

    if ($result =~ $API_RESULT_AUTH) {
        return;
    }

    if (not defined $status) {
        logger("invalid API response: $response");
        failure();
    }

    if ($result =~ $API_RESULT_ENROLL) {
        logger("user $username is not enrolled: $status");
        failure();
    }
    elsif ($result =~ $API_RESULT_DENY) {
        logger("preauth failure for $username: $status");
        failure();
    }
    elsif ($result =~ $API_RESULT_ALLOW) {
        logger("preauth success for $username: $status");
        success();
    }
    else {
        logger("unknown preauth result: $result");
        failure();
    }
}


sub logger {
    my $msg = shift;
    syslog('info', "Duo OpenVPN: $msg");
}


sub success {
    logger("writing success code to $control");

    open CONTROL, '>', $control or die "Error [$control]: $!";
    print CONTROL '1';
    close CONTROL;

    exit 0;
}


sub failure {
    logger("writing failure code to $control");

    open CONTROL, '>', $control or die "Error [$control]: $!";
    print CONTROL '0';
    close CONTROL;

    exit 1;
}
