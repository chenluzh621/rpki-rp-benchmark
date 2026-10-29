#!/bin/sh

# ca1.mft retains roa1-1.roa's name and hash, but the object is absent from
# both RRDP and rsync. RFC 9286 failed-fetch handling excludes the ca1 branch.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"

OBJECT_NAME="roa1-1.roa"
OBJECT="sandbox/rsyncd/content/$TEST/ca1/$OBJECT_NAME"
OBJECT_URI="rsync://localhost:8873/rpki/$TEST/ca1/$OBJECT_NAME"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
UPDATED_SNAPSHOT="$SANDBOX/snapshot-without-$OBJECT_NAME.xml"

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS

# Verify the object and its matching signed manifest entry before deleting it.
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
	|| fail "ca1.mft does not contain $OBJECT_NAME's matching hash"

# Remove exactly one RRDP publish element for the object.
awk -v marker="  <publish uri=\"$OBJECT_URI\">" '
	$0 == marker {
		matches++
		removing = 1
		next
	}
	removing && $0 == "  </publish>" {
		removing = 0
		next
	}
	!removing { print }
	END { if (matches != 1 || removing) exit 1 }
' "$SNAPSHOT" > "$UPDATED_SNAPSHOT" \
	|| fail "Cannot remove $OBJECT_URI from $SNAPSHOT"
mv "$UPDATED_SNAPSHOT" "$SNAPSHOT"
rm "$OBJECT"

test ! -e "$OBJECT" || fail "$OBJECT_NAME still exists in rsync"
if grep -Fq "$OBJECT_URI" "$SNAPSHOT"; then
	fail "$OBJECT_NAME still exists in the RRDP snapshot"
fi
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
