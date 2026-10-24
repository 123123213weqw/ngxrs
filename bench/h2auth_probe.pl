#!/usr/bin/env perl
# Deviation N3 repro: nginx answers 400 for malformed :authority and for a
# control character in a header value; the `h2` crate rejects the stream before
# routing, so ngxrs can never produce that 400.
#
#   perl bench/h2auth_probe.pl [port]      # default 19960
#
# Needs a running server with `http2 on;` on that port. Point it at nginx first
# to see the reference behaviour, then at ngxrs.
use strict;
use warnings;
use lib ($ENV{TESTS_DIR} || "$ENV{HOME}/nginx-tests") . "/lib";
use Test::Nginx::HTTP2;

my $port = shift || 19960;

sub probe {
    my ($label, $headers) = @_;
    my $s = Test::Nginx::HTTP2->new($port);
    my $sid = $s->new_stream({ headers => $headers });
    my $frames = $s->read(all => [{ sid => $sid, fin => 1 }], wait => 0.6);
    my @types = map { $_->{type} } @$frames;
    my ($h) = grep { $_->{type} eq "HEADERS" } @$frames;
    printf("%-26s frames=[%s] status=%s\n", $label, join(",", @types),
        $h ? $h->{headers}{":status"} : "-");
}

my @base = ({ name => ":method", value => "GET", mode => 0 },
            { name => ":scheme", value => "http", mode => 0 },
            { name => ":path",   value => "/",   mode => 0 });

probe("empty authority",   [ @base, { name => ":authority", value => "", mode => 1 } ]);
probe("esc+slash authority",[ @base, { name => ":authority", value => "\e/xample.com", mode => 1 } ]);
probe("ipv6 slash authority",[ @base, { name => ":authority", value => "[abcd\::ef98:0:7654:321/]:12", mode => 1 } ]);
probe("control in host hdr",[ @base, { name => "host", value => "localhost\x02", mode => 1 } ]);
