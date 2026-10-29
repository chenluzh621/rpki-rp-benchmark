#!/bin/sh

# Shared helpers for CMS signature-integrity tests.  The test ROA and its
# containing manifest are changed after BaRRy has generated a valid repository.

ROA="sandbox/rsyncd/content/$TEST/ca1/roa1-1.roa"
MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
CMS_WORK="$SANDBOX/cms-signature"

# The repository metadata must describe the mutated ROA, otherwise an RP would
# reject it at the manifest-hash check before reaching CMS verification.
. "$SRCDIR/../../der-decoding/common.sh"

prepare_valid_roa() {
	mkdir -p "$CMS_WORK"
	unset BARRY_GENERATE_KEYS
	run_barry

	cp "$ROA" "$CMS_WORK/original.roa"
	ORIGINAL_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

	openssl cms -verify -binary -inform DER -in "$ROA" -noverify \
		-out "$CMS_WORK/original-content.der" \
		-signer "$CMS_WORK/ee.pem" \
		> "$CMS_WORK/original-verify.log" 2>&1 \
		|| fail "The original $ROA does not have a valid CMS signature"

	# BaRRy currently emits one 2048-bit RSA CMS signature as the final DER
	# value.  Validate that layout before any test relies on the last 256 bytes.
	openssl asn1parse -inform DER -in "$ROA" \
		> "$CMS_WORK/original-asn1.txt" 2>&1 \
		|| fail "Cannot parse the original $ROA"
	tail -n 1 "$CMS_WORK/original-asn1.txt" \
		| grep -Eq 'd=5[[:space:]]+hl=4 l=[[:space:]]*256 prim:[[:space:]]+OCTET STRING' \
		|| fail "$ROA does not end in the expected CMS signature OCTET STRING"
	tail -c 256 "$ROA" > "$CMS_WORK/original-signature.bin"
}

assert_invalid_cms_signature() {
	if openssl cms -verify -binary -inform DER -in "$ROA" -noverify \
		-out "$CMS_WORK/unexpected-verified-content.der" \
		> "$CMS_WORK/mutated-verify.log" 2>&1; then
		fail "The mutated $ROA unexpectedly passed CMS verification"
	fi
}

publish_mutated_roa() {
	MUTATED_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)
	test "$MUTATED_ROA_HASH" != "$ORIGINAL_ROA_HASH" \
		|| fail "$ROA did not change"

	rehash_and_resign_manifest \
		"$MANIFEST" "$ORIGINAL_ROA_HASH" "$MUTATED_ROA_HASH"
	replace_snapshot_object "$SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ca1/roa1-1.roa" "$ROA"
	replace_snapshot_object "$SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" "$MANIFEST"
	realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"
}

check_only_target_roa_rejected() {
	check_vrps \
		"10.1.2.0/24-24 => AS64502" \
		"10.2.1.0/24-24 => AS64503" \
		"10.2.2.0/24-24 => AS64504"

	check_http_requests \
		"/$TEST/ta.cer 200" \
		"/$TEST/notification.xml 200" \
		"/$TEST/snapshot.xml 200"
	check_rsync_requests
}
