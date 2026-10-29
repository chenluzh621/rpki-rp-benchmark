#!/bin/sh

# Publish a modified roa1-1.roa while leaving ca1.mft's original hash intact.
# Both RRDP and rsync expose the same modified bytes.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"

OBJECT_NAME="roa1-1.roa"
OBJECT="sandbox/rsyncd/content/$TEST/ca1/$OBJECT_NAME"
OBJECT_URI="rsync://localhost:8873/rpki/$TEST/ca1/$OBJECT_NAME"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS

# Confirm that the pristine object's hash is exactly the value signed into
# ca1.mft before introducing the mismatch.
ORIGINAL_HASH=$(sha256sum "$OBJECT" | cut -d' ' -f1 \
	| tr '[:lower:]' '[:upper:]')
FILE_FIELD=$(awk -F, -v name="$OBJECT_NAME" '
	$1 == "ca1.mft" && $3 == "IA5String" && $4 == name &&
	$2 ~ /\.file$/ { print $2 }
' "$SANDBOX/barry.txt")
test -n "$FILE_FIELD" || fail "ca1.mft does not list $OBJECT_NAME"
HASH_FIELD="${FILE_FIELD%.file}.hash"
grep -Fq "ca1.mft,$HASH_FIELD,BIT STRING,0x$ORIGINAL_HASH" \
	"$SANDBOX/barry.txt" \
	|| fail "ca1.mft did not initially contain $OBJECT_NAME's hash"

# Append one byte after BaRRy has completed and signed ca1.mft. The manifest
# keeps the original hash while both repository transports serve changed bytes.
truncate -s +1 "$OBJECT"
MUTATED_HASH=$(sha256sum "$OBJECT" | cut -d' ' -f1 \
	| tr '[:lower:]' '[:upper:]')
test "$MUTATED_HASH" != "$ORIGINAL_HASH" \
	|| fail "$OBJECT_NAME's hash did not change"

replace_snapshot_object "$SNAPSHOT" "$OBJECT_URI" "$OBJECT"
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
