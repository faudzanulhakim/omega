#!/usr/bin/perl
# omega/adapters/analyze.pl — Perl static analyzer for HTTP response bodies.
#
# Protocol (JSON lines, one record per line):
#   stdin : {"url": "...", "body": "..."}          (body may be empty)
#   stdout: {"url": "...", "endpoints": [...], "headers_hits": [...],
#            "suspicious": [...]}
#
# Analysis (Perl regex, read-only, on the supplied body text only):
#   endpoints    — absolute http(s) URLs + paths carrying common
#                  file extensions (.js/.php/.bak/...)
#   headers_hits — sensitive header patterns present in the text
#                  (Set-Cookie, Server, X-Powered-By, ...)
#   suspicious   — high-entropy tokens >= 20 chars (possible secrets)
#
# Never crashes the pipeline: per-line errors emit a JSON error record.

use strict;
use warnings;
use JSON::PP;

binmode STDIN,  ':encoding(UTF-8)';
binmode STDOUT, ':encoding(UTF-8)';

my $URL_RE      = qr{(https?://[A-Za-z0-9._~:/?#\[\]@!\$\&'()*+,;=%-]+)};
my $EXT_RE      = qr{((?:[A-Za-z0-9._~/-]+)\.(?:js|json|php|asp|aspx|jsp|do|cgi|html?|css|xml|bak|old|orig|conf|cfg|ini|env|sql|zip|gz|tgz|tar|log|txt|ya?ml|pem|key)\b)}i;
my $TOKEN_RE    = qr{([A-Za-z0-9+/=_-]{20,})};

my @HEADER_PATTERNS = (
    'set-cookie',
    'x-powered-by',
    'server:',
    'access-control-allow-origin',
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'authorization',
    'api-key',
    'basic-auth',
);

sub entropy {
    my ($s) = @_;
    return 0.0 unless length $s;
    my %freq;
    $freq{$_}++ for split //, $s;
    my $h = 0.0;
    for my $c (values %freq) {
        my $p = $c / length $s;
        $h -= $p * log($p) / log(2);
    }
    return $h;
}

sub analyze_one {
    my ($rec) = @_;
    my $url  = exists $rec->{url}  ? $rec->{url}  : '';
    my $body = exists $rec->{body} ? $rec->{body} : '';

    my (%endpoints, %hits, %susp);
    my @hits;
    if (defined $body && length $body) {
        # absolute URLs
        while ($body =~ /$URL_RE/g) {
            my $u = $1;
            $u =~ s/[.,;)\]'"]+$//;        # trim trailing punctuation
            $endpoints{$u} = 1 if length $u;
        }
        # paths with interesting file extensions
        while ($body =~ /$EXT_RE/g) {
            my $p = $1;
            $endpoints{$p} = 1;
        }
        # header-ish patterns
        for my $pat (@HEADER_PATTERNS) {
            push @hits, $pat if $body =~ /\Q$pat\E/i;
        }
        # high-entropy tokens (>= 20 chars, entropy >= 3.0)
        while ($body =~ /$TOKEN_RE/g) {
            my $t = $1;
            next if $t =~ /^[0-9]+$/;               # long numbers
            next if entropy($t) < 3.0;
            next if $t =~ /^(?:[A-Fa-f0-9]{2})+$/ && entropy($t) < 3.5;
            $susp{$t} = 1;
        }
    }

    my @ep_keys = sort keys %endpoints;
    my @eps = @ep_keys > 50 ? @ep_keys[0 .. 49] : @ep_keys;
    my @susp_keys = sort { entropy($b) <=> entropy($a) } keys %susp;
    my @susp = @susp_keys > 20 ? @susp_keys[0 .. 19] : @susp_keys;

    return {
        url          => $url,
        endpoints    => [@eps],
        headers_hits => [@hits],
        suspicious   => [@susp],
    };
}

while (my $line = <STDIN>) {
    $line =~ s/^\s+|\s+$//g;
    next unless length $line;
    my $rec;
    eval {
        $rec = JSON::PP::decode_json($line);
        1;
    } or do {
        print JSON::PP->new->canonical->encode(
            { url => '', error => "bad json line: $@" }), "\n";
        next;
    };
    eval {
        print JSON::PP->new->canonical->encode(analyze_one($rec)), "\n";
        1;
    } or do {
        print JSON::PP->new->canonical->encode(
            { url => ($rec->{url} // ''), error => "analysis failed: $@" }), "\n";
    };
}

exit 0;
