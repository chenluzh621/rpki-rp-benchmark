#!/bin/sh

# The two distinct ROA EE certificates issued by ca1 use the same subject
# Name. Both ca1 VRPs must be excluded.
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
