#!/bin/sh

# Duplicate the embedded EE certificate in roa1-1.roa SignedData.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../cms-signature/common.sh"
. "$SRCDIR/../common.sh"

prepare_valid_roa
mutate_signed_data_optional_fields "$ROA" certificates-multiple

openssl asn1parse -inform DER -in "$ROA" \
	> "$CMS_WORK/certificates-multiple-asn1.txt" 2>&1 \
	|| fail "The multiple-certificates ROA is not valid DER"
openssl cms -verify -binary -inform DER -in "$ROA" -noverify -nosigs \
	-out "$CMS_WORK/mutated-content.der" \
	> "$CMS_WORK/mutated-content-extract.log" 2>&1 \
	|| fail "Cannot extract eContent from the multiple-certificates ROA"
cmp -s "$CMS_WORK/original-content.der" "$CMS_WORK/mutated-content.der" \
	|| fail "Duplicating certificates unexpectedly changed ROA eContent"

publish_mutated_roa
run_rp
check_only_target_roa_rejected
