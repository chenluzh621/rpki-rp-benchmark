#!/bin/sh

# A CA certificate with a negative serial number is non-conforming to
# RFC 6487 section 4.2. Its subordinate branch must not produce VRPs.
. tools/checks.sh
. rp/$RP.sh

# Generate independent keys for every object, as the baseline test does.
BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS
run_rp

# ca1.cer has serial number -1, so only ca2 remains valid.
check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
