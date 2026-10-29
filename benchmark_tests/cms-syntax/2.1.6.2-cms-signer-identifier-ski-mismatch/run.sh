#!/bin/sh

# roa1-1.roa uses a 20-octet SignerIdentifier SKI that differs from its EE SKI.
. tools/checks.sh
. rp/$RP.sh

BARRY_GENERATE_KEYS=1
run_barry
unset BARRY_GENERATE_KEYS

SID_SKI=$(awk -F, '
	$1 == "roa1-1.roa" &&
	$2 == "obj.content.signerInfos.0.sid.subjectKeyIdentifier" { print $4 }
' "$SANDBOX/barry.txt")
EE_SKI=$(awk -F, '
	$1 == "roa1-1.roa" &&
	$2 == "obj.content.certificates.0.tbsCertificate.extensions.ski.extnValue" {
		print $4
	}
' "$SANDBOX/barry.txt")
test "$SID_SKI" = "0x000102030405060708090A0B0C0D0E0F10111213" \
	|| fail "roa1-1.roa does not contain the intended SignerIdentifier SKI"
test -n "$EE_SKI" && test "$SID_SKI" != "$EE_SKI" \
	|| fail "roa1-1.roa SignerIdentifier SKI unexpectedly matches its EE SKI"

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
