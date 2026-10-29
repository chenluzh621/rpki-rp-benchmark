#!/bin/sh

# Verify that a ROA truncated after repository generation is rejected during
# ASN.1 decoding, while the other objects at the publication point remain valid.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

ROA="sandbox/rsyncd/content/$TEST/ca1/roa1-1.roa"
MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
TRUNCATE_BYTES=16

# The manifest re-signing step needs BaRRy's deterministic test key pool.
unset BARRY_GENERATE_KEYS
run_barry

ORIGINAL_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)
ROA_SIZE=$(wc -c < "$ROA")
test "$ROA_SIZE" -gt "$TRUNCATE_BYTES" \
	|| fail "$ROA is too small to truncate by $TRUNCATE_BYTES bytes"
truncate -s "$((ROA_SIZE - TRUNCATE_BYTES))" "$ROA"
MUTATED_ROA_HASH=$(sha256sum "$ROA" | cut -d' ' -f1)

# Keep repository consistency checks green so the RP reaches ASN.1 decoding.
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

check_logfile fort1 -F "roa1-1.roa: Error '1' decoding ASN.1 object"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"
check_rsync_requests
