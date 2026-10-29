#!/bin/sh

# roa1-1.roa declares SHA-512 instead of SHA-256 in SignerInfo.digestAlgorithm.
. tools/checks.sh
. rp/$RP.sh

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS

grep -Fq \
	'roa1-1.roa,obj.content.signerInfos.0.digestAlgorithm.algorithm,OBJECT IDENTIFIER,2.16.840.1.101.3.4.2.3 (sha512)' \
	"$SANDBOX/barry.txt" \
	|| fail "roa1-1.roa does not use SHA-512 as SignerInfo.digestAlgorithm"

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
