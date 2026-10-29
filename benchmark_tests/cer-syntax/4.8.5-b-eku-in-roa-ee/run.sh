#!/bin/sh

# Convert roa1-1.roa's EE placeholder into a non-critical EKU, re-sign the
# embedded certificate, and restore the ROA manifest and RRDP hashes.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../4.8.5-common.sh"

ROA="sandbox/rsyncd/content/$TEST/ca1/roa1-1.roa"
CA="sandbox/rsyncd/content/$TEST/ta/ca1.cer"
MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
WORK="$SANDBOX/certificate-update"

unset BARRY_GENERATE_KEYS
run_barry
mkdir -p "$WORK"

ORIGINAL_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)
openssl cms -verify -binary -inform DER -in "$ROA" -noverify -nosigs \
	-out /dev/null -certsout "$WORK/original-ee.pem" \
	> "$WORK/extract.log" 2>&1 || fail "Cannot extract ROA EE certificate"
openssl x509 -in "$WORK/original-ee.pem" -outform DER \
	-out "$WORK/original-ee.cer" || fail "Cannot encode ROA EE certificate"

eku_mutate_certificate "$WORK/original-ee.cer" \
	"$WORK/mutated-ee.cer" "$WORK/tbs.der"
eku_resign_certificate "$WORK/mutated-ee.cer" "$WORK/tbs.der" "$CA" \
	"$WORK/signature.bin" "$WORK/resigned-ee.cer" "$WORK/ca-public.pem"
eku_replace_binary_blob "$ROA" "$WORK/original-ee.cer" \
	"$WORK/resigned-ee.cer" "$WORK/updated.roa"

openssl x509 -inform DER -in "$WORK/resigned-ee.cer" -noout \
	-ext extendedKeyUsage > "$WORK/eku.txt" 2>&1 \
	|| fail "Mutated ROA EE certificate is not valid DER"
grep -Fq "1.3.6.1.5.5.7.3.1.1.1" "$WORK/eku.txt" \
	|| fail "ROA EE certificate does not contain the intended EKU"
openssl cms -verify -binary -inform DER -in "$WORK/updated.roa" \
	-noverify -out /dev/null > "$WORK/cms-verify.log" 2>&1 \
	|| fail "ROA CMS signature does not verify after certificate replacement"

mv "$WORK/updated.roa" "$ROA"
MUTATED_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

rehash_and_resign_manifest \
	"$MANIFEST" "$ORIGINAL_ROA_HASH" "$MUTATED_ROA_HASH"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ca1/roa1-1.roa" "$ROA"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" "$MANIFEST"
realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"

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
