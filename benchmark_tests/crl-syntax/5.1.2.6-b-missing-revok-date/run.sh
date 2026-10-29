#!/bin/sh

# Remove revocationDate from ca1.crl's only revoked-certificate entry while
# retaining userCertificate. The ca1 branch must be rejected.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

crl_mutation_init
mutate_first_crl_entry missing-date "$CRL" "$WORK/mutated.crl"
extract_tbs_cert_list "$WORK/mutated.crl" "$WORK/tbs.der"
openssl dgst -sha256 -sign "$CRL_KEY" -out "$WORK/signature.bin" \
	"$WORK/tbs.der" || fail "Cannot re-sign ca1.crl"
replace_crl_signature "$WORK/mutated.crl" "$WORK/signature.bin" \
	"$WORK/resigned.crl"
mv "$WORK/resigned.crl" "$CRL"

openssl asn1parse -inform DER -in "$CRL" \
	> "$WORK/asn1.txt" 2>&1 || fail "Mutated ca1.crl is not valid DER"
if openssl crl -inform DER -in "$CRL" -noout \
	> "$WORK/schema-check.txt" 2>&1; then
	fail "ca1.crl still decodes despite its missing revocation date"
fi
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
