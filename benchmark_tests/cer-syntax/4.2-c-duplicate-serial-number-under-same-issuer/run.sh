#!/bin/sh

# The two ROA EE certificates issued by ca1 deliberately share a serial
# number. Treat both certificates as non-conforming to RFC 6487 section 4.2;
# the independent ca2 branch must remain valid.
. tools/checks.sh
. rp/$RP.sh

# Independent keys ensure these are distinct EE certificates whose only
# issuer/serial identity collision is the deliberately duplicated serial.
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
