#!/bin/sh

# ca1.mft has a nextUpdate earlier than thisUpdate. The entire ca1 branch
# must be rejected.
. tools/checks.sh
. rp/$RP.sh

# Keep both values near the validation time while preserving nextUpdate <
# thisUpdate. The reversed interval cannot contain the current time by design.
MFT_THIS_UPDATE=$(date -u -d '1 hour' '+%Y-%m-%dT%H:%M:%SZ')
MFT_NEXT_UPDATE=$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ')
export MFT_THIS_UPDATE MFT_NEXT_UPDATE

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
