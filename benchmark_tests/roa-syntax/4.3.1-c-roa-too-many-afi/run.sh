#!/bin/sh

# Give roa1-1.roa three families: IPv4, IPv6, and a second IPv4 family.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../common.sh"

unset BARRY_GENERATE_KEYS
run_barry
mutate_roa_afi too-many
run_rp

check_vrps \
	"10.1.2.0/24-24 => AS64502" \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
