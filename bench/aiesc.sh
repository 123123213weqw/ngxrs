#!/usr/bin/env bash
# Derive nginx autoindex's href escaping empirically.
#
# Two things are observable from the rendered HTML and neither is guessable:
#   1. which characters are percent-encoded in the href  (NGX_ESCAPE_URI_COMPONENT)
#   2. which characters are HTML-escaped in the label    (ngx_escape_html)
# so every printable ASCII character is put into a filename and the output read back.
set -uo pipefail

ROOT=/home/wzu/ngxrs
BASE=/tmp/aiesc
PORT=18933
D=$BASE/www

rm -rf "$BASE"; mkdir -p "$D" "$BASE/logs"
: >"$BASE/logs/access.log"; : >"$BASE/logs/error.log"

# One file per character; the filename is "c" + char + "z" so the character is
# never first or last (which could interact with truncation).
python3 - "$D" <<'PY'
import os, sys
d = sys.argv[1]
for code in range(0x20, 0x7f):
    ch = chr(code)
    if ch == '/':
        continue          # cannot appear in a filename
    name = "c%sz" % ch
    try:
        open(os.path.join(d, name), "w").close()
    except OSError:
        pass
PY

cat >"$BASE/nginx.conf" <<EOF
worker_processes 1;
daemon off;
pid $BASE/nginx.pid;
error_log $BASE/err.log warn;
events { worker_connections 1024; }
http {
    include $ROOT/conf/mime.types;
    default_type application/octet-stream;
    server {
        listen 127.0.0.1:$PORT;
        server_name localhost;
        location / { root $D; autoindex on; }
    }
}
EOF

"$ROOT/../nginx-baseline/sbin/nginx" -c "$BASE/nginx.conf" -p "$BASE" 2>"$BASE/start.err" &
sleep 1.5

if ! curl -sf "http://127.0.0.1:$PORT/" -o "$BASE/out.html"; then
    echo "PROBE FAILED"; tail -3 "$BASE/start.err"; exit 1
fi

[ -f "$BASE/nginx.pid" ] && kill "$(cat "$BASE/nginx.pid")" 2>/dev/null

# Report, per character: the href text and the label text nginx produced.
python3 - "$BASE/out.html" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8", errors="surrogateescape").read()
rows = re.findall(r'<a href="([^"]*)">(.*?)</a>', html, re.S)
by_name = {}
for href, label in rows:
    by_name[href] = label

print("char  href_body              label")
out_href = []
out_label = []
for code in range(0x20, 0x7f):
    ch = chr(code)
    if ch == '/':
        continue
    # locate the row whose label, when un-HTML-escaped, is c<ch>z
    want = "c%sz" % ch
    found = None
    for href, label in rows:
        plain = (label.replace("&lt;", "<").replace("&gt;", ">")
                      .replace("&amp;", "&").replace("&quot;", '"'))
        if plain.rstrip() == want:
            found = (href, label.rstrip())
            break
    if found is None:
        continue
    href, label = found
    out_href.append((ch, href))
    out_label.append((ch, label))

print("--- href: characters that are percent-encoded ---")
enc = [ch for ch, h in out_href if h != "c%sz" % ch]
print("ESCAPED IN HREF: " + repr("".join(enc)))
print("--- label: characters that are html-escaped ---")
esc = [ch for ch, l in out_label if l != "c%sz" % ch]
print("ESCAPED IN LABEL: " + repr("".join(esc)))
print("--- samples ---")
for ch, h in out_href:
    if h != "c%sz" % ch:
        print("  %r -> %r" % (ch, h))
for ch, l in out_label:
    if l != "c%sz" % ch:
        print("  label %r -> %r" % (ch, l))
PY
