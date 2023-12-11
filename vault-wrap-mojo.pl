#!/usr/bin/perl
use strict;
use warnings;

=head1 Description

VOTS -- Vault Based One-Time Secret Service

Uses a Vault wrapping token to store a secret (or a file, think securely sharing sensitive documents). 

Wrapped tokens are inherently short-lived, and will burn after use, which makes them great for a one time secret sharing backend.

=cut

use Data::Dumper;

use Net::Subnet 'subnet_matcher';
use Restish::Client;

use Mojolicious::Lite -signatures;
plugin 'RenderFile';

# Vault URI
my $URI = $ENV{uri};

# Token with proper permisssions to generate a wrapped token
# NOTE:  Ideally we'd have 2 tokens, one for reading and one for writing
#     A write-only token protects itself from being able to read back secrets
my $TOKEN = $ENV{token};

# App server IP/Port
my $IP = $ENV{listen_ip};
my $PORT = $ENV{listen_port};

my $MAX_UPLOAD= 768;

app->config(
    hypnotoad => {
        listen  => ["http://$IP:$PORT"],
        workers => 10, proxy => 1,
    }
);

# New secret form
get '/' => sub ($c) {
    $c->render(template => "new-secret"); 
};

# Alias for new secret form
get '/secret' => sub ($c) {
    $c->render(template => "new-secret");
};

# Protected file form
get '/file' => sub ($c) {
    $c->render(template => "new-file-upload", max_upload=> $MAX_UPLOAD);
};

# This will create a new secret
post '/secret' => sub ($c) {
    my $secret = $c->param('secret');
    my ($time,$seconds) = param_check_time($c) or return;

    my $vault = vault($TOKEN);

    $vault->head_params_default({'X-Vault-Wrap-TTL' => $seconds, 'X-Vault-Token' => $TOKEN });

    # This should really be a subroutine
    my $res = $vault->request(
        method => "POST",
        uri => "v1/sys/wrapping/wrap",
        body_params => { secret => $secret }
    );

    $res->{wrap_info}{token} or return $c->render(text => 'Could not finish the request', status => 500);

    $c->render(text => $res->{wrap_info}{token});
    $c->respond_to(
        html => {
            template => "secret-link", secret => $res->{wrap_info}{token}, time => $time
        },
        json => { json => $res->{wrap_info}{token}, },
    );

};

# This will create a new secret
post '/file' => sub ($c) {
    my $secret = $c->param('secret');
    my ($time,$seconds) = param_check_time($c) or return;

    use MIME::Base64;
    my $ctype = $secret->headers->content_type();
    my $asset = $secret->asset();
    my $filename = $secret->filename;
    my $size = $asset->size;

    # For now vault entries are limited.  Some compression could allow us to grow this exponentially.
    # Also, chopping up the file into multiple wrapped tokens and returning a single token which would
    # instruct the code to pull down a list of tokens and rebuild the file, is a viable option
    return $c->render(text => "File too big, $MAX_UPLOAD KB max", status => 500) if $size > $MAX_UPLOAD*1024;

    # base64 to convert the binary into something vault can wrap
    $secret = encode_base64($asset->slurp());

    my $vault = vault($TOKEN);

    $vault->head_params_default({'X-Vault-Wrap-TTL' => $seconds, 'X-Vault-Token' => $TOKEN });

    my $res = $vault->request(
        method => "POST",
        uri => "v1/sys/wrapping/wrap",
        body_params => { secret => $secret, content_type => $ctype, filename => $filename}
    );

    $res->{wrap_info}{token} or return $c->render(text => 'Could not finish the request', status => 500);

    $c->render(text => $res->{wrap_info}{token});
    $c->respond_to(
        html => {
            template => "secret-link-file", secret => $res->{wrap_info}{token}, time => $time
        },
        json => { json => $res->{wrap_info}{token}, },
    );
};

# Instead of providing the secret, provide a "link to the secret".  Useful for preventing Slack/email/etc from opening your secret effectively burning it
get '/link/#token' => sub ($c) {
    my $token = $c->param('token');

    unless ($token =~ /^[a-zA-Z0-9.]+$/) {
        return $c->render(text => 'Invalid Token Format', status => 400);
    }

    $c->respond_to(
        html => {
            template => "link-secret", secret => $token,
        },
    );
};

# View the secret.  Optionally return json if instructed
get '/secret/#token' => sub ($c) {
    my $token = $c->param('token');

    unless ($token =~ /^[a-zA-Z0-9.]+$/) {
        return $c->render(text => 'Invalid Token Format', status => 400);
    }

    my $vault = vault($token)
        or return $c->render(text => 'Could not create vault object', status => 500);

    my $vres = $vault->request(
        method => 'POST',
        uri => 'v1/sys/wrapping/unwrap',
    ) or return $c->render(text => 'Could not finish the request', status => 500);

    if (!$vres or !$vres->{data}) {
        return $c->render(text => 'Invalid Token', status => 400);
    }

    $c->respond_to(
        html => {
            template => "view-secret", secret => $vres->{data}
        },
        json => {json => $vres->{data}, },
    );
};

# Provide the file, directly in the browser, as the content-type originally specified
get '/file/#token' => sub ($c) {
    my $token = $c->param('token');

    unless ($token =~ /^[a-zA-Z0-9.]+$/) {
        return $c->render(text => 'Invalid Token Format', status => 400);
    }

    my $vault = vault($token)
        or return $c->render(text => 'Could not create vault object', status => 500);

    my $vres = $vault->request(
        method => 'POST',
        uri => 'v1/sys/wrapping/unwrap',
    ) or return $c->render(text => 'Could not finish the request', status => 500);

    if (!$vres or !$vres->{data}) {
        return $c->render(text => 'Invalid Token', status => 400);
    }

    $c->res->headers->content_type($vres->{data}{content_type});
    $c->render(data=>decode_base64($vres->{data}{secret}));

};

# Instruct the browser to download the file
get '/dfile/#token' => sub ($c) {
    my $token = $c->param('token');

    unless ($token =~ /^[a-zA-Z0-9.]+$/) {
        return $c->render(text => 'Invalid Token Format', status => 400);
    }

    my $vault = vault($token)
        or return $c->render(text => 'Could not create vault object', status => 500);

    my $vres = $vault->request(
        method => 'POST',
        uri => 'v1/sys/wrapping/unwrap',
    ) or return $c->render(text => 'Could not finish the request', status => 500);

    if (!$vres or !$vres->{data}) {
        return $c->render(text => 'Invalid Token', status => 400);
    }

   $c->render_file('data' => decode_base64($vres->{data}{secret}), 'filename' => $vres->{data}{filename});
};

# Catchall 404
any '*' => sub ($c) {
    $c->render(text => 404, status => 404);
};

app->log( Mojo::Log->new( path => "LOGFILE", level => 'debug' ) );
app->start;

sub vault {
    my $token = shift || $TOKEN;
    my $client = Restish::Client->new(
        uri_host => $URI,
        agent_options => { },
    );

    # Add a token to the new client if we have a token
    $client->head_params_default({'X-Vault-Token' => $token });

    return $client;
}

# Ensures the time period of the secret (lives for N days) is sane.
# return undef on fail
# returns array of times on success
sub param_check_time {
    my $c = shift;
    my $time = $c->param('time');
    unless ($time =~ /^\d+$/) {
        $c->render(text=> "FAIL MODE", status => 500);
        return;
    }
    unless ($time) {
        $c->render(text=> "FAIL MODE", status => 500);
        return; 
    }

    $time =30 if $time > 30;
    return $time, $time *3600*24;
}
