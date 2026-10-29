#!/bin/sh

# A valid roa1-extra.roa is published through RRDP and rsync but omitted from
# ca1.mft. It must be ignored without causing the ca1 fetch to fail.
. tools/checks.sh
. rp/$RP.sh

EXTRA_NAME="roa1-extra.roa"
EXTRA_OBJECT="sandbox/rsyncd/content/$TEST/ca1/$EXTRA_NAME"
EXTRA_URI="rsync://localhost:8873/rpki/$TEST/ca1/$EXTRA_NAME"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS

# Prove that the extra object is present in both transports, is a valid signed
# CMS object, and is not accidentally included in ca1.mft's fileList.
test -f "$EXTRA_OBJECT" || fail "$EXTRA_NAME was not generated"
grep -Fq "<publish uri=\"$EXTRA_URI\">" "$SNAPSHOT" \
	|| fail "$EXTRA_NAME is absent from the RRDP snapshot"
openssl cms -verify -binary -inform DER -in "$EXTRA_OBJECT" -noverify \
	-out "$SANDBOX/extra-content.der" \
	> "$SANDBOX/extra-verify.log" 2>&1 \
	|| fail "$EXTRA_NAME is not a valid signed CMS object"
if awk -F, -v name="$EXTRA_NAME" '
	$1 == "ca1.mft" && $3 == "IA5String" && $4 == name &&
	$2 ~ /\.file$/ { found = 1 }
	END { exit found ? 0 : 1 }
' "$SANDBOX/barry.txt"; then
	fail "ca1.mft unexpectedly lists $EXTRA_NAME"
fi

run_rp

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
