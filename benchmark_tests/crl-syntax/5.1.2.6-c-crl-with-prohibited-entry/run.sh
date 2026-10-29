#!/bin/sh

# Add the reasonCode CRL-entry extension to ca1.crl. RFC 6487 permits no
# CRL-entry extensions, so the ca1 branch must be rejected.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

crl_mutation_init
mutate_first_crl_entry reason-code "$CRL" "$WORK/mutated.crl"
extract_tbs_cert_list "$WORK/mutated.crl" "$WORK/tbs.der"
openssl dgst -sha256 -sign "$CRL_KEY" -out "$WORK/signature.bin" \
	"$WORK/tbs.der" || fail "Cannot re-sign ca1.crl"
replace_crl_signature "$WORK/mutated.crl" "$WORK/signature.bin" \
	"$WORK/resigned.crl"
mv "$WORK/resigned.crl" "$CRL"

openssl crl -inform DER -in "$CRL" -text -noout \
	> "$WORK/crl.txt" 2>&1 || fail "Mutated ca1.crl is not valid DER"
grep -Fq "X509v3 CRL Reason Code" "$WORK/crl.txt" \
	|| fail "ca1.crl does not contain the reasonCode entry extension"
openssl x509 -inform DER -in "$CA" -pubkey -noout > "$WORK/ca-public.pem"
openssl dgst -sha256 -verify "$WORK/ca-public.pem" \
	-signature "$WORK/signature.bin" "$WORK/tbs.der" \
	> "$WORK/verify.log" 2>&1 \
	|| fail "The re-signed ca1.crl does not verify"

publish_mutated_crl
run_rp

check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"
check_rsync_requests
