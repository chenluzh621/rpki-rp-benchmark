#!/bin/sh

# ca1.mft lists the real file roa1+1.roa with its correct hash. The '+' is
# the only defect: RFC 9286 section 4.2.2 does not permit it in file names.
. tools/checks.sh
. rp/$RP.sh

BAD_NAME="roa1+1.roa"
BAD_OBJECT="sandbox/rsyncd/content/$TEST/ca1/$BAD_NAME"

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS

# Prove that the listed object exists and that BaRRy's completed manifest
# contains the SHA-256 of exactly that file.
test -f "$BAD_OBJECT" || fail "$BAD_OBJECT was not generated"
BAD_HASH=$(sha256sum "$BAD_OBJECT" | cut -d' ' -f1 \
	| tr '[:lower:]' '[:upper:]')
FILE_FIELD=$(awk -F, -v name="$BAD_NAME" '
	$1 == "ca1.mft" && $3 == "IA5String" && $4 == name &&
	$2 ~ /\.file$/ { print $2 }
' "$SANDBOX/barry.txt")
test -n "$FILE_FIELD" || fail "ca1.mft does not list $BAD_NAME"
test "$(printf '%s\n' "$FILE_FIELD" | sed '/^$/d' | wc -l)" -eq 1 \
	|| fail "ca1.mft lists $BAD_NAME more than once"
HASH_FIELD="${FILE_FIELD%.file}.hash"
grep -Fq "ca1.mft,$HASH_FIELD,BIT STRING,0x$BAD_HASH" \
	"$SANDBOX/barry.txt" \
	|| fail "ca1.mft does not contain $BAD_NAME's matching SHA-256"

run_rp

check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
