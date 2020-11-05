#!/usr/bin/perl

# This file contains user acceptance tests for rpc_service.py
# Only basic sanity tests around authentication as the program isn't meant to
# be consumed without any changes and `jsonrpcserver` itself validates much of
# the errors as per JSON-RPC spec.

# Before running this file:
# 1. $ pipenv shell
# 2. Set any required env vars like: $ SOME_VAR=SOME_VAL flask run
#  or provide a different env file: $ DOTENV_PATH=/path/to/file flask run
# 3. and run `$ perl test_rpc_service.pl`

# WARNING: Use a separate SHELF_NAME for testing

# Sample Usage:
# On first terminal:
#   $ pipenv shell
#   $ SHELF_NAME=test_store.db FLASK_ENV=development TESTING=True flask run
# On second terminal:
#   $ pipenv shell
#   $ SHELF_NAME=test_store.db perl test_rpc_service.pl

# Note: Use Data::Dumper to dump request/response from rpc_service

use strict;
use warnings;
use feature qw(say);
use Test::More;
use JSON::PP;

# Required info for rest of the test
my $http    = 'POST';
my $type    = 'application/json';
my $ep      = "localhost:$ENV{'SERVER_PORT'}";
my $pub_ep  = "$ep/public";
my $priv_ep = "$ep/private";
my $id      = 1;

=head
Params:
    method (SCALAR) - Name of the method to invoke from rpc_service
    params (HASH) - If any params are required by the method
Returns:
    JSON encoded string.
=cut

my $get_json = sub {
    my ($method, $params) = @_;
    my $hash = { 'jsonrpc' => '2.0', 'id' => $id, 'method' => $method };
    if (defined $params) {
        $hash->{'params'} = $params;
    }
    $id++;
    return encode_json($hash);
};

=head
Params:
    json_str (SCALAR) - JSON encoded string
    ep (SCALAR) - Public/Private Endpoint
    token - JWT token
Returns:
    `curl` compatible request string
=cut

my $get_req = sub {
    my ($json_str, $ep, $token) = @_;
    my $req = "curl --silent -X POST -H 'Content-Type: $type' ";
    if (defined $token) {
        chomp($token);
        $req .= "-H 'x-access-token: $token' ";
    }
    $req .= "-d '$json_str' $ep";
    return $req;
};

my $get_res = sub {
    my ($req_str) = @_;
    my $temp_res = `$req_str`;
    chomp($temp_res);
    my $dec_res = decode_json $temp_res;
    return $dec_res;
};

=head
Returns:
    JSESSION string and as part of testing, only ADMIN_USER credentials are used
    to perform this operation
=cut

my $get_jsession_id = sub {
    my $res =
`curl --silent  -v -u $ENV{'JIRA_USERNAME'}:$ENV{'JIRA_PASSWORD'} $ENV{'JIRA_SERVER'}/rest/auth/latest/session -H "Content-Type: $type" 2>&1 | grep cookie`;
    my $matches = () = $res =~ /cookie/gs;

    # --- Test ---
    cmp_ok($matches, '==', 2,
        'Test: Two cookies should be set from jira when authenticated')
      or BAIL_OUT "Can't proceed without authentication";

    my ($jsession_id) = $res =~ /(?<=JSESSIONID=)(\w+)(?=;)/;
    return "$jsession_id";
};

# Test helper
my $check_result = sub {
    my ($res, $msg) = @_;
    isnt($res->{'result'}, undef, $msg);
};

# Test helper
my $check_error = sub {
    my ($res, $msg) = @_;
    isnt($res->{'error'}, undef, $msg);
};

say '=' x 10 . ' START ' . '=' x 10;

# TODO: Implement a test to differentiate between Production and Testing shelf
ok(-e $ENV{'SHELF_NAME'}, 'Test: Python shelf exists in current directory');

# Existing users in Shelf
my $users = [ $ENV{'ADMIN_USER'} ];

# --- Test ---
my $jsession_id = $get_jsession_id->();
my $req         = $get_req->(
    $get_json->(
        'get_token', { 'name' => $ENV{'ADMIN_USER'}, 'jsessionid' => $jsession_id },
    ),
    $pub_ep
);
my $res = $get_res->($req);
$check_result->(
    $res,
    'Test: User should be able to use JSESSION ID to authenticate against Jira'
);

# --- Test ---
my ($token) = $res->{'result'} =~ /Token: b'(.*)?'/s;
isnt($token, undef,
    'Test: get_token after successful authentication should return a token');

# --- Test ---
$req = $get_req->(
    $get_json->(
        'get_token', { 'name' => $ENV{'ADMIN_USER'}, 'jsessionid' => $jsession_id },
    ),
    $pub_ep
);
$res = $get_res->($req);
$check_error->($res,
    'Test: JSESSION ID should be invalidated after single use');

# --- Test ---
$req = $get_req->(
    $get_json->(
        'get_token',
        {
            'name'       => $ENV{'ADMIN_USER'},
            'jsessionid' => $jsession_id,
            'skip_auth'  => 1,
        }
    ),
    $pub_ep
);
$res = $get_res->($req);
$check_result->(
    $res, 'Test: ADMIN should be able to authenticate service without JSESSION ID'
);

# --- Test ---
($token) = $res->{'result'} =~ /Token: b'(.*)?'/s;
$req = $get_req->($get_json->('get_all_users'), $priv_ep, $token);
$res = $get_res->($req);
$check_result->($res, 'Test: Admin should be able to get existing users');

# --- Test ---
$req = $get_req->($get_json->('get_all_users'), $priv_ep);
$res = $get_res->($req);
like(
    $res->{'message'},
    qr/token is missing/i,
    'Test: Private ep should only be accessed with token'
);

# --- Test ---
$req = $get_req->($get_json->('get_all_users'), $pub_ep);
$res = $get_res->($req);
$check_error->(
    $res, 'Test: get_all_users should only be accessed from private ep'
);

# --- Test ---
for my $run (1 .. 4) {
    my $user = 'user_' . $run;
    $req =
      $get_req->($get_json->('add_user', { 'name' => $user }), $priv_ep, $token);
    $res = $get_res->($req);
    push @$users, $user;
    $check_result->($res, "Test: Add $user to shelf");
}

# --- Test ---
$req = $get_req->($get_json->('get_all_users'), $priv_ep, $token);
$res = $get_res->($req);
$check_result->($res, 'Test: Should return all users after addition');

# --- Test ---
is_deeply($res->{'result'}, $users, 'Test: All users in shelf are validated');

# --- Test ---
$req = $get_req->(
    $get_json->(
        'get_token', { 'name' => 'not_existing', 'jsessionid' => $jsession_id }
    ),
    $pub_ep
);
$res = $get_res->($req);
$check_error->($res, 'Test: User not added by ADMIN should not get token');

# Get a token with 1 minute expiry
my $user       = 'user_4';
my $user_token = `pyjwt --key=$ENV{'JWT_SECRET'} encode sub=$user exp=+60`;

# --- Test ---
$req = $get_req->($get_json->('get_all_users'), $priv_ep, $user_token);
$res = $get_res->($req);
$check_error->($res, 'Test: Normal user should not be able to get all users');

# --- Test ---
$req = $get_req->(
    $get_json->('to_done', { 'issue_id' => 'RHGSQE-736' }),
    $priv_ep, $user_token
);
$res = $get_res->($req);
$check_error->(
    $res,
    'Test: User who is not a assignee should not be able to access Jira service'
);

# --- Test ---
my $fake_user = 'fake_user';
$req = $get_req->(
    $get_json->('add_user', { 'name' => $fake_user }),
    $priv_ep, $user_token
);
$res = $get_res->($req);
$check_error->($res, 'Test: Normal user should not be able to add new users');

# --- Test ---
my $fake_token =
  `pyjwt --key=$ENV{'JWT_SECRET'} encode sub=$fake_user exp=+300`;
$req = $get_req->(
    $get_json->('to_done', { 'issue_id' => 'RHGSQE-736' }),
    $priv_ep, $fake_token
);
$res = $get_res->($req);
$check_error->(
    $res, 'Test: User not in shelf but a valid token should not access service'
);

# --- Test --
$req = $get_req->(
    $get_json->('to_done', { 'issue_id' => 'RHGSQE' }),
    $priv_ep, $token
);
$res = $get_res->($req);
$check_error->(
    $res, 'Test: User should provide valid issue id to mark the fields'
);

# --- Test ---
my $temp_token =
  `pyjwt --key=$ENV{'JWT_SECRET'} encode sub=$ENV{'ADMIN_USER'} exp=+5`;
sleep(6);    # Test for token expiry
$req = $get_req->($get_json->('get_all_users'), $priv_ep, $temp_token);
$res = $get_res->($req);
like($res->{'message'}, qr/expired/i,
    'Test: Private ep should only be accessed with token');

# --- Test ---
$req = $get_req->($get_json->('get_all_users'), $priv_ep, $token);
$res = $get_res->($req);
is_deeply($res->{'result'}, $users,
    'Test: Make sure no fake user is added by end of test');

done_testing(23);

say '=' x 10 . ' END ' . '=' x 10;
