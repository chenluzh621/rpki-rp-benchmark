#!/bin/sh

# ca1.mft's EE certificate explicitly lists 10.1.0.0/16 instead of inheriting
# IP resources from ca1. RFC 9286 section 5.1 requires rejecting that manifest.
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
