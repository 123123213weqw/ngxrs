#!/usr/bin/env bash
# Run TLS suites that `Test::Nginx` gates behind `has('openssl:1.0.2')`.
#
# That gate greps `nginx -V` for the string `built with OpenSSL <version>`.
# ngxrs terminates TLS with rustls, not OpenSSL, so it never prints that line
# and the suites skip on our side -- which silently turns "unmeasured" into
# "not failing". Lying in `-V` would be wrong, so instead we run those files
# against a Test::Nginx whose openssl gate reports the capability as present.
#
# The patch must be applied *in place*: every .t starts with `use lib 'lib'`
# after `chdir($FindBin::Bin)`, which prepends the suite's own `lib` to @INC
# and beats PERL5LIB. A patched copy placed on PERL5LIB is therefore never
# loaded -- the suites re-skip and it looks like the override did nothing.
#
# The change is narrow: only the `openssl:VERSION` branch, only when
# TNGX_ALLOW_OPENSSL_GATE=1. The pristine file is restored on exit.
set -uo pipefail
DIR="$(dirname "$0")"
SUITE="${TESTS_DIR:-$HOME/nginx-tests}"
TARGET="$SUITE/lib/Test/Nginx.pm"

if [ ! -f "$TARGET" ]; then
  echo "cannot find $TARGET" >&2
  exit 2
fi

BACKUP="$(mktemp)"
cp "$TARGET" "$BACKUP"
restore() { cp "$BACKUP" "$TARGET"; rm -f "$BACKUP"; }
trap restore EXIT INT TERM

python3 - "$TARGET" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = '\tif ($feature =~ /^(openssl|libressl):([0-9.]+)([a-z]*)/) {'
new = (
    '\tif ($feature =~ /^(openssl|libressl):([0-9.]+)([a-z]*)/) {\n'
    '\t\t# ngxrs terminates TLS with rustls, so `nginx -V` prints no\n'
    '\t\t# "built with OpenSSL" line and this gate would skip the suite on\n'
    '\t\t# our side regardless of behaviour. Opt-in override only.\n'
    '\t\treturn 1 if $ENV{TNGX_ALLOW_OPENSSL_GATE};'
)
if old not in s:
    sys.exit("gate anchor not found -- upstream harness changed?")
open(p, "w").write(s.replace(old, new, 1))
print("patched openssl gate in place")
PY

LIST="${TEST_LIST:-ssl_certificate.t ssl_certificate_cache.t ssl_certificate_aux.t ssl_conf_command.t ssl_sni_protocols.t ssl_password_file.t proxy_ssl_certificate_cache.t proxy_ssl_conf_command.t stream_ssl_certificate.t stream_ssl_certificate_cache.t stream_proxy_ssl_certificate_cache.t stream_ssl_conf_command.t stream_proxy_ssl_conf_command.t stream_ssl_sni_protocols.t mail_ssl_conf_command.t uwsgi_ssl_certificate.t uwsgi_ssl_certificate_vars.t}"

export TNGX_ALLOW_OPENSSL_GATE=1
export TEST_LIST="$LIST"
bash "$DIR/nginxtests.sh"
rc=$?
echo "(pristine harness restored)"
exit $rc
