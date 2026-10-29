#!/bin/sh

# ca1.crl has matching sha1WithRSAEncryption AlgorithmIdentifiers and a valid
# SHA-1/RSA signature, but the RPKI CRL profile requires SHA-256/RSA.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

crl_mutation_init
extract_tbs_cert_list "$CRL" "$WORK/tbs.der"

# BaRRy wrote SHA-1/RSA OIDs but generated SHA-256 signature bytes. Replace
# them with a genuine SHA-1/RSA signature over the unchanged TBSCertList.
openssl dgst -sha1 -sign "$CRL_KEY" -out "$WORK/signature.bin" \
	"$WORK/tbs.der" || fail "Cannot re-sign ca1.crl with SHA-1/RSA"
replace_crl_signature "$CRL" "$WORK/signature.bin" "$WORK/resigned.crl"
mv "$WORK/resigned.crl" "$CRL"

openssl crl -inform DER -in "$CRL" -text -noout \
	> "$WORK/crl.txt" 2>&1 || fail "Mutated ca1.crl is not valid DER"
test "$(grep -c 'Signature Algorithm: sha1WithRSAEncryption' "$WORK/crl.txt")" -eq 2 \
	|| fail "ca1.crl's two signature AlgorithmIdentifiers are not SHA-1/RSA"
openssl x509 -inform DER -in "$CA" -pubkey -noout > "$WORK/ca-public.pem"
openssl dgst -sha1 -verify "$WORK/ca-public.pem" \
	-signature "$WORK/signature.bin" "$WORK/tbs.der" \
	> "$WORK/verify.log" 2>&1 \
	|| fail "The SHA-1/RSA signature on ca1.crl does not verify"

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
