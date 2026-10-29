#!/bin/sh

# Duplicate roa1-1.roa's IPv4 ROAIPAddressFamily so both AFIs are IPv4.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../common.sh"

unset BARRY_GENERATE_KEYS
run_barry
mutate_roa_afi duplicated
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
