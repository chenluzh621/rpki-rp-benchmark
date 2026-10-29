#!/bin/sh

# ca1.cer's AKI does not identify ta.cer's public key (the issuer SKI).
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

generate_repository

TA_SKI=$(openssl x509 -inform DER -in "$CPV_TA" -noout \
	-ext subjectKeyIdentifier | tr -cd '0-9A-Fa-f' | tail -c 41)
CA1_AKI=$(openssl x509 -inform DER -in "$CPV_CA1" -noout \
	-ext authorityKeyIdentifier | tr -cd '0-9A-Fa-f' | tail -c 41)
test -n "$TA_SKI" && test -n "$CA1_AKI" \
	|| fail "Cannot read ta.cer's SKI or ca1.cer's AKI"
test "$TA_SKI" != "$CA1_AKI" \
	|| fail "ca1.cer's AKI unexpectedly matches ta.cer's SKI"

run_rp
check_ca1_branch_rejected
