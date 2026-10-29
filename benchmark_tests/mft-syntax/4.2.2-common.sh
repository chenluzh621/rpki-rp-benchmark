#!/bin/sh

# Shared helpers for tests that mutate and re-sign ca1.mft after BaRRy has
# generated an otherwise valid repository.
. "$SRCDIR/../../der-decoding/common.sh"

# $1: Manifest path
# $2: Work directory
extract_manifest_content() {
	MFT_HELPER_MANIFEST="$1"
	MFT_HELPER_WORK="$2"
	mkdir -p "$MFT_HELPER_WORK"

	openssl cms -verify -binary -inform DER \
		-in "$MFT_HELPER_MANIFEST" -noverify -nosigs \
		-out "$MFT_HELPER_WORK/content.der" \
		-signer "$MFT_HELPER_WORK/ee.pem" \
		> "$MFT_HELPER_WORK/extract.log" 2>&1 \
		|| fail "Cannot extract $MFT_HELPER_MANIFEST"
}

# Re-sign a mutated Manifest eContent, verify the result, then publish the
# replacement through both rsync and RRDP.
# $1: Manifest path
# $2: Mutated eContent path
# $3: Work directory containing ee.pem
# $4: RRDP snapshot path
# $5: RRDP notification path
resign_and_publish_manifest() {
	MFT_HELPER_MANIFEST="$1"
	MFT_HELPER_CONTENT="$2"
	MFT_HELPER_WORK="$3"
	MFT_HELPER_SNAPSHOT="$4"
	MFT_HELPER_NOTIFICATION="$5"

	MFT_HELPER_EE_HASH=$(openssl x509 \
		-in "$MFT_HELPER_WORK/ee.pem" -pubkey -noout \
		| openssl pkey -pubin -outform DER 2> /dev/null \
		| sha256sum | cut -d' ' -f1)
	MFT_HELPER_KEY=""
	for MFT_HELPER_KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
		MFT_HELPER_KEY_HASH=$(openssl pkey -in "$MFT_HELPER_KEY_FILE" \
			-pubout -outform DER 2> /dev/null \
			| sha256sum | cut -d' ' -f1)
		if test "$MFT_HELPER_KEY_HASH" = "$MFT_HELPER_EE_HASH"; then
			MFT_HELPER_KEY="$MFT_HELPER_KEY_FILE"
			break
		fi
	done
	test -n "$MFT_HELPER_KEY" \
		|| fail "Cannot find the private key for $MFT_HELPER_MANIFEST"

	openssl cms -sign -binary -nodetach -noindef -keyid -nosmimecap \
		-md sha256 -econtent_type 1.2.840.113549.1.9.16.1.26 \
		-in "$MFT_HELPER_CONTENT" \
		-signer "$MFT_HELPER_WORK/ee.pem" -inkey "$MFT_HELPER_KEY" \
		-outform DER -out "$MFT_HELPER_WORK/resigned.mft" \
		> "$MFT_HELPER_WORK/sign.log" 2>&1 \
		|| fail "Cannot re-sign $MFT_HELPER_MANIFEST"

	openssl cms -verify -binary -inform DER \
		-in "$MFT_HELPER_WORK/resigned.mft" -noverify \
		-out "$MFT_HELPER_WORK/verified-content.der" \
		> "$MFT_HELPER_WORK/verify.log" 2>&1 \
		|| fail "The re-signed $MFT_HELPER_MANIFEST does not verify"
	cmp -s "$MFT_HELPER_CONTENT" "$MFT_HELPER_WORK/verified-content.der" \
		|| fail "The re-signed Manifest contains unexpected content"
	mv "$MFT_HELPER_WORK/resigned.mft" "$MFT_HELPER_MANIFEST"

	replace_snapshot_object "$MFT_HELPER_SNAPSHOT" \
		"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" \
		"$MFT_HELPER_MANIFEST"
	realign_snapshot_hash "$MFT_HELPER_SNAPSHOT" "$MFT_HELPER_NOTIFICATION"
}
