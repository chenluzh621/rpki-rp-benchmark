#!/bin/sh

# RFC 5280 section 5.1.2.1 requires a CRL that uses extensions to be v2.
# ca1.crl carries the normal AKI and CRL Number extensions but declares v1,
# so the ca1 branch must not contribute VRPs. The independent ca2 branch
# remains valid.
. tools/checks.sh
. rp/$RP.sh

# Generate independent keys for every object, as the baseline test does.
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
