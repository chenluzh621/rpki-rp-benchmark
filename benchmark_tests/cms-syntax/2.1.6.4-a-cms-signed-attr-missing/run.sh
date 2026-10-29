#!/bin/sh

# Rebuild roa1-1.roa with an absent SignerInfo.signedAttrs field while keeping
# its eContent and EE certificate, and creating a valid signature over eContent.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../cms-signature/common.sh"

prepare_valid_roa

EE_KEY_HASH=$(openssl x509 -in "$CMS_WORK/ee.pem" -pubkey -noout \
	| openssl pkey -pubin -outform DER 2> /dev/null \
	| sha256sum | cut -d' ' -f1)
EE_KEY=""
for KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
	KEY_HASH=$(openssl pkey -in "$KEY_FILE" -pubout -outform DER \
		2> /dev/null | sha256sum | cut -d' ' -f1)
	if test "$KEY_HASH" = "$EE_KEY_HASH"; then
		EE_KEY="$KEY_FILE"
		break
	fi
done
test -n "$EE_KEY" || fail "Cannot find the private key for roa1-1.roa"

openssl cms -sign -binary -nodetach -noindef -keyid -nosmimecap -noattr \
	-md sha256 -econtent_type 1.2.840.113549.1.9.16.1.24 \
	-in "$CMS_WORK/original-content.der" \
	-signer "$CMS_WORK/ee.pem" -inkey "$EE_KEY" \
	-outform DER -out "$CMS_WORK/no-signed-attrs.roa" \
	> "$CMS_WORK/no-signed-attrs-sign.log" 2>&1 \
	|| fail "Cannot rebuild roa1-1.roa without signedAttrs"

openssl cms -cmsout -inform DER -in "$CMS_WORK/no-signed-attrs.roa" -print \
	> "$CMS_WORK/no-signed-attrs-print.txt" 2>&1 \
	|| fail "Cannot decode the rebuilt roa1-1.roa"
awk '
	$1 == "signedAttrs:" { getline; if ($1 == "<ABSENT>") found = 1 }
	END { exit !found }
' "$CMS_WORK/no-signed-attrs-print.txt" \
	|| fail "The rebuilt roa1-1.roa still contains signedAttrs"

openssl cms -verify -binary -inform DER \
	-in "$CMS_WORK/no-signed-attrs.roa" -noverify \
	-out "$CMS_WORK/no-signed-attrs-content.der" \
	> "$CMS_WORK/no-signed-attrs-verify.log" 2>&1 \
	|| fail "The rebuilt roa1-1.roa does not have a valid CMS signature"
cmp -s "$CMS_WORK/original-content.der" \
	"$CMS_WORK/no-signed-attrs-content.der" \
	|| fail "Removing signedAttrs unexpectedly changed the ROA eContent"

mv "$CMS_WORK/no-signed-attrs.roa" "$ROA"
publish_mutated_roa

run_rp
check_only_target_roa_rejected
