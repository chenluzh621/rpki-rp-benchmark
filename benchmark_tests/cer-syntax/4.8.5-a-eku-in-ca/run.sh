#!/bin/sh

# Convert ca1.cer's equal-length placeholder into a non-critical EKU,
# re-sign the certificate, and restore repository consistency.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../4.8.5-common.sh"

CA="sandbox/rsyncd/content/$TEST/ta/ca1.cer"
TA="sandbox/rsyncd/content/$TEST/ta.cer"
MANIFEST="sandbox/rsyncd/content/$TEST/ta/ta.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
WORK="$SANDBOX/certificate-update"

unset BARRY_GENERATE_KEYS
run_barry
mkdir -p "$WORK"

ORIGINAL_CA_HASH=$(sha256sum "$CA" | cut -d' ' -f1)
eku_mutate_certificate "$CA" "$WORK/mutated-ca.cer" "$WORK/tbs.der"
eku_resign_certificate "$WORK/mutated-ca.cer" "$WORK/tbs.der" "$TA" \
	"$WORK/signature.bin" "$WORK/resigned-ca.cer" "$WORK/ta-public.pem"
mv "$WORK/resigned-ca.cer" "$CA"
MUTATED_CA_HASH=$(sha256sum "$CA" | cut -d' ' -f1)

openssl x509 -inform DER -in "$CA" -noout -ext extendedKeyUsage \
	> "$WORK/eku.txt" 2>&1 || fail "Mutated ca1.cer is not valid DER"
grep -Fq "1.3.6.1.5.5.7.3.1.1.1" "$WORK/eku.txt" \
	|| fail "ca1.cer does not contain the intended EKU"

rehash_and_resign_manifest \
	"$MANIFEST" "$ORIGINAL_CA_HASH" "$MUTATED_CA_HASH"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ta/ca1.cer" "$CA"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ta/ta.mft" "$MANIFEST"
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
