#!/bin/sh

# roa1-1.roa uses the forbidden nonzero ROA version. Only this ROA must be
# rejected; the other three ROAs remain valid.
. tools/checks.sh
. rp/$RP.sh

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS
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
