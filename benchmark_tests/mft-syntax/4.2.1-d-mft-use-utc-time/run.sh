#!/bin/sh

# ca1.mft encodes thisUpdate as UTCTime instead of GeneralizedTime. Re-sign
# the deliberately malformed eContent so the ASN.1 type is the only reason
# to reject the manifest.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"

MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
MFT_WORK="$SANDBOX/manifest-update"

# Re-signing requires BaRRy's deterministic test key pool.
unset BARRY_GENERATE_KEYS
run_barry
mkdir -p "$MFT_WORK"

openssl cms -verify -binary -inform DER \
	-in "$MANIFEST" -noverify -nosigs \
	-out "$MFT_WORK/content.der" \
	-signer "$MFT_WORK/ee.pem" \
	> "$MFT_WORK/extract.log" 2>&1 \
	|| fail "Cannot extract $MANIFEST"

# Manifest ::= SEQUENCE. Locate the first GeneralizedTime after
# manifestNumber, convert YYYYMMDDHHMMSSZ to YYMMDDHHMMSSZ, and change only
# its ASN.1 tag from 0x18 (GeneralizedTime) to 0x17 (UTCTime).
perl - "$MFT_WORK/content.der" "$MFT_WORK/content-mutated.der" <<'PERL'
use strict;
use warnings;

my ($input, $output) = @ARGV;
open my $fh, '<:raw', $input or die "Cannot open $input: $!\n";
local $/;
my $der = <$fh>;
close $fh;

sub tlv {
	my ($data, $offset) = @_;
	die "Truncated DER tag\n" if $offset + 2 > length($data);
	my $tag = ord(substr($data, $offset, 1));
	my $first = ord(substr($data, $offset + 1, 1));
	my ($header, $length);
	if ($first < 128) {
		$header = 2;
		$length = $first;
	} else {
		my $count = $first & 0x7f;
		die "Unsupported DER length\n" if $count < 1 || $count > 4;
		die "Truncated DER length\n" if $offset + 2 + $count > length($data);
		$header = 2 + $count;
		$length = 0;
		for my $i (0 .. $count - 1) {
			$length = ($length << 8)
				| ord(substr($data, $offset + 2 + $i, 1));
		}
	}
	die "Truncated DER value\n"
		if $offset + $header + $length > length($data);
	return ($tag, $header, $length, $header + $length);
}

sub der_length {
	my ($length) = @_;
	return chr($length) if $length < 128;
	my $encoded = '';
	while ($length > 0) {
		$encoded = chr($length & 0xff) . $encoded;
		$length >>= 8;
	}
	return chr(0x80 | length($encoded)) . $encoded;
}

my ($outer_tag, $outer_header, $outer_length, $outer_total) = tlv($der, 0);
die "Manifest eContent is not a SEQUENCE\n" if $outer_tag != 0x30;
die "Trailing data after Manifest eContent\n" if $outer_total != length($der);

my $at = $outer_header;
my $end = $outer_header + $outer_length;
my $seen_manifest_number = 0;
my $target;
while ($at < $end) {
	my ($tag, undef, undef, $total) = tlv($der, $at);
	if (!$seen_manifest_number && $tag == 0x02) {
		$seen_manifest_number = 1;
	} elsif ($seen_manifest_number && $tag == 0x18) {
		$target = $at;
		last;
	}
	$at += $total;
}
die "Cannot locate thisUpdate GeneralizedTime\n" if !defined $target;

my (undef, $time_header, $time_length, $time_total) = tlv($der, $target);
my $time = substr($der, $target + $time_header, $time_length);
die "Unexpected GeneralizedTime encoding: $time\n"
	if $time !~ /^\d{14}Z$/;
my $year = substr($time, 0, 4);
die "Year $year is outside the UTCTime range\n"
	if $year < 1950 || $year > 2049;
my $utc_time = substr($year, 2, 2) . substr($time, 4);
my $replacement = "\x17" . der_length(length($utc_time)) . $utc_time;

my $content = substr($der, $outer_header, $target - $outer_header)
	. $replacement
	. substr($der, $target + $time_total,
		$end - $target - $time_total);
my $mutated = "\x30" . der_length(length($content)) . $content;

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $mutated;
close $out;
PERL
test "$?" -eq 0 || fail "Cannot encode ca1.mft thisUpdate as UTCTime"

openssl asn1parse -inform DER -in "$MFT_WORK/content-mutated.der" \
	> "$MFT_WORK/asn1.txt" 2>&1 \
	|| fail "Mutated manifest eContent is not valid DER"
grep -Fq 'UTCTIME' "$MFT_WORK/asn1.txt" \
	|| fail "Mutated manifest does not contain UTCTime"

# Find the deterministic private key matching the manifest EE certificate.
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
test -n "$MFT_KEY" || fail "Cannot find ca1.mft's private key"

openssl cms -sign -binary -nodetach -noindef -keyid -nosmimecap \
	-md sha256 -econtent_type 1.2.840.113549.1.9.16.1.26 \
	-in "$MFT_WORK/content-mutated.der" \
	-signer "$MFT_WORK/ee.pem" -inkey "$MFT_KEY" \
	-outform DER -out "$MFT_WORK/resigned.mft" \
	> "$MFT_WORK/sign.log" 2>&1 \
	|| fail "Cannot re-sign $MANIFEST"

openssl cms -verify -binary -inform DER \
	-in "$MFT_WORK/resigned.mft" -noverify \
	-out "$MFT_WORK/verified-content.der" \
	> "$MFT_WORK/verify.log" 2>&1 \
	|| fail "The re-signed $MANIFEST does not verify"
cmp -s "$MFT_WORK/content-mutated.der" "$MFT_WORK/verified-content.der" \
	|| fail "The re-signed $MANIFEST contains unexpected content"
mv "$MFT_WORK/resigned.mft" "$MANIFEST"

# Publish the replacement through RRDP as well as rsync.
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ca1/ca1.mft" "$MANIFEST"
realign_snapshot_hash "$SNAPSHOT" "$NOTIFICATION"

run_rp

check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
