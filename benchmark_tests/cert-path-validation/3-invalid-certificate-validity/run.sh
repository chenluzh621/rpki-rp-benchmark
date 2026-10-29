#!/bin/sh

# ca1.cer's interval is well formed but does not include validation time.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

generate_repository

NOT_BEFORE=$(openssl x509 -inform DER -in "$CPV_CA1" -noout \
	-startdate | sed 's/^notBefore=//')
NOT_AFTER=$(openssl x509 -inform DER -in "$CPV_CA1" -noout \
	-enddate | sed 's/^notAfter=//')
test "$NOT_BEFORE" = "Jan  1 00:00:00 2030 GMT" \
	|| fail "ca1.cer has unexpected notBefore: $NOT_BEFORE"
test "$NOT_AFTER" = "Jan  1 00:00:00 2031 GMT" \
	|| fail "ca1.cer has unexpected notAfter: $NOT_AFTER"

run_rp
check_ca1_branch_rejected
