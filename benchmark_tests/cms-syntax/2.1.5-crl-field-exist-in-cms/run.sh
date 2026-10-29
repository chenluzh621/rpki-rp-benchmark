#!/bin/sh

# Insert ca1.crl into the forbidden SignedData.crls field of ca1.mft. The
# invalid manifest must remove the entire ca1 branch from validated output.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../cms-signature/common.sh"
. "$SRCDIR/../common.sh"

CRL="sandbox/rsyncd/content/$TEST/ca1/ca1.crl"
MFT_CMS_WORK="$SANDBOX/cms-crls"
mkdir -p "$MFT_CMS_WORK"

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS

cp "$MANIFEST" "$MFT_CMS_WORK/original.mft"
ORIGINAL_MFT_HASH=$(sha256sum "$MANIFEST" | cut -d' ' -f1)
openssl cms -verify -binary -inform DER -in "$MANIFEST" -noverify \
	-out "$MFT_CMS_WORK/original-content.der" \
	> "$MFT_CMS_WORK/original-verify.log" 2>&1 \
	|| fail "The original ca1.mft does not have a valid CMS signature"

mutate_signed_data_optional_fields "$MANIFEST" crls-add "$CRL"

openssl asn1parse -inform DER -in "$MANIFEST" \
	> "$MFT_CMS_WORK/crls-asn1.txt" 2>&1 \
	|| fail "The ca1.mft containing SignedData.crls is not valid DER"
openssl cms -verify -binary -inform DER -in "$MANIFEST" -noverify -nosigs \
	-out "$MFT_CMS_WORK/mutated-content.der" \
	> "$MFT_CMS_WORK/mutated-content-extract.log" 2>&1 \
	|| fail "Cannot extract eContent from ca1.mft after adding crls"
cmp -s "$MFT_CMS_WORK/original-content.der" \
	"$MFT_CMS_WORK/mutated-content.der" \
	|| fail "Adding SignedData.crls unexpectedly changed manifest eContent"

MUTATED_MFT_HASH=$(sha256sum "$MANIFEST" | cut -d' ' -f1)
test "$MUTATED_MFT_HASH" != "$ORIGINAL_MFT_HASH" \
	|| fail "Adding SignedData.crls did not change ca1.mft"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" "$MANIFEST"
realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"

run_rp
check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"
check_rsync_requests
