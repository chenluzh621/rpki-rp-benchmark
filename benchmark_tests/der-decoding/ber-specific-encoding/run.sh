#!/bin/sh

# Verify that a BER-valid but DER-forbidden indefinite-length ContentInfo is
# rejected, while the other objects at the publication point remain valid.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

ROA="sandbox/rsyncd/content/$TEST/ca1/roa1-1.roa"
MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
MUTATED_ROA="$SANDBOX/roa1-1.mutated"

# The manifest re-signing step needs BaRRy's deterministic test key pool.
unset BARRY_GENERATE_KEYS
run_barry

ORIGINAL_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

# ContentInfo is an outer SEQUENCE. Replace its definite DER length with the
# BER indefinite form, retain the original contents, and terminate with EOC.
TAG_OCTET=$(od -An -tu1 -j0 -N1 "$ROA" | tr -d ' ')
test "$TAG_OCTET" -eq 48 || fail "$ROA does not start with a SEQUENCE"
LENGTH_OCTET=$(od -An -tu1 -j1 -N1 "$ROA" | tr -d ' ')
if test "$LENGTH_OCTET" -lt 128; then
	CONTENT_OFFSET=2
else
	LENGTH_OCTETS=$((LENGTH_OCTET - 128))
	test "$LENGTH_OCTETS" -ge 1 -a "$LENGTH_OCTETS" -le 4 \
		|| fail "Unsupported outer DER length in $ROA"
	CONTENT_OFFSET=$((2 + LENGTH_OCTETS))
fi

{
	printf '\060\200'
	tail -c "+$((CONTENT_OFFSET + 1))" "$ROA"
	printf '\000\000'
} > "$MUTATED_ROA"
openssl asn1parse -inform DER -in "$MUTATED_ROA" \
	> /dev/null 2>&1 || fail "The indefinite-length mutation is not valid BER"
mv "$MUTATED_ROA" "$ROA"
MUTATED_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

# Keep repository consistency checks green so DER enforcement is the only
# reason to reject this otherwise valid signed object.
rehash_and_resign_manifest \
	"$MANIFEST" "$ORIGINAL_ROA_HASH" "$MUTATED_ROA_HASH"

# RRDP is the normal first choice. Publish both changed objects in the existing
# snapshot, then align the unsigned snapshot hash in notification.xml.
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
