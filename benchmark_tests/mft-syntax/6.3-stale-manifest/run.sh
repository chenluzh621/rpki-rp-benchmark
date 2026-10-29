#!/bin/sh

# ca1.mft has a correctly ordered validity interval, but nextUpdate is already
# in the past. RFC 9286 section 6.3 requires treating ca1 as a failed fetch.
. tools/checks.sh
. rp/$RP.sh

MFT_THIS_UPDATE=$(date -u -d '2 hours ago' '+%Y-%m-%dT%H:%M:%SZ')
MFT_NEXT_UPDATE=$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ')
export MFT_THIS_UPDATE MFT_NEXT_UPDATE

# Guard the test's premise before generating the repository: thisUpdate must
# precede nextUpdate, and nextUpdate must precede the current time.
THIS_EPOCH=$(date -u -d "$MFT_THIS_UPDATE" '+%s')
NEXT_EPOCH=$(date -u -d "$MFT_NEXT_UPDATE" '+%s')
NOW_EPOCH=$(date -u '+%s')
test "$THIS_EPOCH" -lt "$NEXT_EPOCH" \
	|| fail "thisUpdate is not earlier than nextUpdate"
test "$NEXT_EPOCH" -lt "$NOW_EPOCH" \
	|| fail "nextUpdate is not stale"

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
