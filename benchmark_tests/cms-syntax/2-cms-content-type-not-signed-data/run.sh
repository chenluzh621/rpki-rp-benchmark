#!/bin/sh

# roa1-1.roa identifies its outer CMS ContentInfo as id-data instead of the
# id-signedData content type required for RPKI signed objects.
. tools/checks.sh
. rp/$RP.sh

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS

# Prove that the RD override reached the outermost ContentInfo field.
grep -Fq \
	'roa1-1.roa,obj.contentType,OBJECT IDENTIFIER,1.2.840.113549.1.7.1 (pkcs7-data)' \
	"$SANDBOX/barry.txt" \
	|| fail "roa1-1.roa does not use id-data as its outer CMS content type"

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
