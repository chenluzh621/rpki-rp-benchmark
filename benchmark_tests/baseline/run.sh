#!/bin/sh

# Generate and validate the known-good baseline repository.
. tools/checks.sh
. rp/$RP.sh

# Generate independent keys for every object. The shared deterministic test
# key pool can map different filenames to the same key.
BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS
run_rp

# Each ROA contributes one unique (ASN, prefix, maxLength) VRP payload.
check_vrps \
	"10.1.1.0/24-24 => AS64501" \
	"10.1.2.0/24-24 => AS64502" \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
