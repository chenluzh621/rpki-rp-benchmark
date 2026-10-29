#!/bin/sh

# ca1.cer's DER structure is valid, but its signature does not verify under TA.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

generate_repository

openssl x509 -inform DER -in "$CPV_TA" -out "$CPV_WORK/ta.pem" \
	|| fail "Cannot decode ta.cer"
openssl x509 -inform DER -in "$CPV_CA1" -out "$CPV_WORK/ca1.pem" \
	|| fail "Cannot decode ca1.cer"
if openssl verify -ignore_critical -CAfile "$CPV_WORK/ta.pem" \
	"$CPV_WORK/ca1.pem" > "$CPV_WORK/verify.log" 2>&1; then
	fail "ca1.cer's deliberately invalid signature unexpectedly verifies"
fi
grep -Eqi 'signature failure|verification failure' "$CPV_WORK/verify.log" \
	|| fail "OpenSSL did not report a certificate signature failure"

run_rp
check_ca1_branch_rejected
