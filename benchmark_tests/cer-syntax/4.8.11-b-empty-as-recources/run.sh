#!/bin/sh

# ca1.cer's AS Resources extension has an explicitly empty asnum choice. A
# conforming RP must reject ca1 and its complete subordinate branch.
. tools/checks.sh
. rp/$RP.sh

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS
run_rp

check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
