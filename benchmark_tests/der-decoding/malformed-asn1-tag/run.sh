#!/bin/sh

# Verify that a CMS ContentInfo carrying an unexpected outer ASN.1 tag is
# rejected, while the other objects at the publication point remain valid.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

ROA="sandbox/rsyncd/content/$TEST/ca1/roa1-1.roa"
MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
MUTATED_ROA="$SANDBOX/roa1-1.mutated"

# Reuse the valid baseline RD and deterministic test key pool.
unset BARRY_GENERATE_KEYS
run_barry "../../baseline/rd"

ORIGINAL_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)
ORIGINAL_ROA_SIZE=$(wc -c < "$ROA")

# ContentInfo is a SEQUENCE (tag 0x30). Replace only that tag with SET
# (0x31), which is a valid ASN.1 tag but invalid for the CMS schema.
TAG_OCTET=$(od -An -tu1 -j0 -N1 "$ROA" | tr -d ' ')
test "$TAG_OCTET" -eq 48 || fail "$ROA does not start with a SEQUENCE"
{
	printf '\061'
	tail -c +2 "$ROA"
} > "$MUTATED_ROA"
test "$(wc -c < "$MUTATED_ROA")" -eq "$ORIGINAL_ROA_SIZE" \
	|| fail "Changing the ASN.1 tag unexpectedly changed the ROA size"

# Generic ASN.1 accepts SET, but CMS decoding must reject it as ContentInfo.
if openssl cms -cmsout -inform DER -in "$MUTATED_ROA" -out /dev/null \
	> "$SANDBOX/cms-parse.log" 2>&1; then
	fail "The malformed ContentInfo tag was unexpectedly accepted"
fi

mv "$MUTATED_ROA" "$ROA"
MUTATED_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

# Keep the manifest and RRDP metadata consistent so ASN.1 decoding is the
# only reason to reject this ROA.
rehash_and_resign_manifest \
	"$MANIFEST" "$ORIGINAL_ROA_HASH" "$MUTATED_ROA_HASH"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ca1/roa1-1.roa" "$ROA"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" "$MANIFEST"
realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"

run_rp

# Only the VRP contributed by roa1-1.roa must disappear.
check_vrps \
	"10.1.2.0/24-24 => AS64502" \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"
check_rsync_requests
