#!/bin/sh

# Replace one file hash in a manifest's eContent and sign the updated content
# with the same manifest EE certificate and its matching test private key.
#
# $1: Manifest path
# $2: Old object hash (hex)
# $3: New object hash (hex)
rehash_and_resign_manifest() {
	MANIFEST="$1"
	OLD_OBJECT_HASH="$2"
	NEW_OBJECT_HASH="$3"
	MFT_WORK="$SANDBOX/manifest-update"

	mkdir -p "$MFT_WORK"

	openssl cms -verify -binary -inform DER \
		-in "$MANIFEST" -noverify -nosigs \
		-out "$MFT_WORK/content.der" \
		-signer "$MFT_WORK/ee.pem" \
		> "$MFT_WORK/extract.log" 2>&1 \
		|| fail "Cannot extract $MANIFEST"

	# Manifest hashes are fixed-size BIT STRING payloads. Require exactly one
	# match so an RD layout change cannot silently update the wrong entry.
	perl - "$MFT_WORK/content.der" "$OLD_OBJECT_HASH" "$NEW_OBJECT_HASH" \
		> "$MFT_WORK/content-updated.der" <<'PERL'
use strict;
use warnings;

my ($path, $old_hex, $new_hex) = @ARGV;
open my $input, '<:raw', $path or die "Cannot open $path: $!\n";
local $/;
my $content = <$input>;
close $input;

my $old = pack('H*', $old_hex);
my $new = pack('H*', $new_hex);
my $count = ($content =~ s/\Q$old\E/$new/g);
die "Expected one manifest hash match, found $count\n" if $count != 1;

binmode STDOUT;
print $content;
PERL
	test "$?" -eq 0 || fail "Cannot update the object hash in $MANIFEST"

	EE_KEY_HASH=$(openssl x509 -in "$MFT_WORK/ee.pem" -pubkey -noout \
		| openssl pkey -pubin -outform DER 2> /dev/null \
		| sha256sum | cut -d' ' -f1)
	MFT_KEY=""
	for KEY_FILE in "${BARRY_KEYS_PATH:-custom/keys}"/*.pem; do
		KEY_HASH=$(openssl pkey -in "$KEY_FILE" -pubout -outform DER \
			2> /dev/null | sha256sum | cut -d' ' -f1)
		if test "$KEY_HASH" = "$EE_KEY_HASH"; then
			MFT_KEY="$KEY_FILE"
			break
		fi
	done
	test -n "$MFT_KEY" || fail "Cannot find the private key for $MANIFEST"

	openssl cms -sign -binary -nodetach -noindef -keyid -nosmimecap \
		-md sha256 -econtent_type 1.2.840.113549.1.9.16.1.26 \
		-in "$MFT_WORK/content-updated.der" \
		-signer "$MFT_WORK/ee.pem" -inkey "$MFT_KEY" \
		-outform DER -out "$MFT_WORK/resigned.mft" \
		> "$MFT_WORK/sign.log" 2>&1 \
		|| fail "Cannot re-sign $MANIFEST"

	# Verify both the new CMS signature and the exact signed content before
	# publishing the replacement manifest.
	openssl cms -verify -binary -inform DER \
		-in "$MFT_WORK/resigned.mft" -noverify \
		-out "$MFT_WORK/verified-content.der" \
		> "$MFT_WORK/verify.log" 2>&1 \
		|| fail "The re-signed $MANIFEST does not verify"
	cmp -s "$MFT_WORK/content-updated.der" "$MFT_WORK/verified-content.der" \
		|| fail "The re-signed $MANIFEST contains unexpected content"

	mv "$MFT_WORK/resigned.mft" "$MANIFEST"
}

# Replace one <publish> payload in an existing RRDP snapshot.
#
# $1: Snapshot path
# $2: Object URI
# $3: Object path
replace_snapshot_object() {
	SNAPSHOT="$1"
	OBJECT_URI="$2"
	OBJECT_PATH="$3"
	PAYLOAD="$SANDBOX/$(basename "$OBJECT_PATH").b64"
	UPDATED_SNAPSHOT="$SANDBOX/snapshot-updated.xml"

	base64 "$OBJECT_PATH" > "$PAYLOAD"
	awk -v marker="  <publish uri=\"$OBJECT_URI\">" -v payload="$PAYLOAD" '
		$0 == marker {
			matches++
			print
			while ((getline line < payload) > 0)
				print line
			close(payload)
			replacing = 1
			next
		}
		replacing && $0 == "  </publish>" {
			replacing = 0
			print
			next
		}
		!replacing { print }
		END { if (matches != 1 || replacing) exit 1 }
	' "$SNAPSHOT" > "$UPDATED_SNAPSHOT" \
		|| fail "Cannot replace $OBJECT_URI in $SNAPSHOT"
	mv "$UPDATED_SNAPSHOT" "$SNAPSHOT"
}

# Recompute the snapshot hash advertised by its RRDP notification file.
#
# $1: Snapshot path
# $2: Notification path
realign_snapshot_hash() {
	SNAPSHOT="$1"
	NOTIFICATION="$2"
	SNAPSHOT_HASH=$(sha256sum "$SNAPSHOT" | cut -d' ' -f1)

	sed -i \
		"s|\(<snapshot uri=\"[^\"]*\" hash=\"\)[0-9a-f]*\(\"/>\)|\1$SNAPSHOT_HASH\2|" \
		"$NOTIFICATION"
	grep -Fq "hash=\"$SNAPSHOT_HASH\"" "$NOTIFICATION" \
		|| fail "Cannot update the snapshot hash in $NOTIFICATION"
}
