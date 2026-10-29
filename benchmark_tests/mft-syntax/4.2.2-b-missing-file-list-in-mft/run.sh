#!/bin/sh

# Remove the complete fileList field from ca1.mft's eContent while preserving
# valid DER framing and a valid CMS signature. The ca1 branch must be rejected.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../4.2.2-common.sh"

MANIFEST="sandbox/rsyncd/content/$TEST/ca1/ca1.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
MFT_WORK="$SANDBOX/manifest-update"

# Re-signing requires BaRRy's deterministic test key pool.
unset BARRY_GENERATE_KEYS
run_barry
extract_manifest_content "$MANIFEST" "$MFT_WORK"

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
		die "Truncated DER length\n"
			if $offset + 2 + $count > length($data);
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
my (@tags, @offsets, @totals);
while ($at < $end) {
	my ($tag, undef, undef, $total) = tlv($der, $at);
	push @tags, $tag;
	push @offsets, $at;
	push @totals, $total;
	$at += $total;
}
die "Manifest child boundary mismatch\n" if $at != $end;
die "Manifest does not end in fileList SEQUENCE\n"
	if !@tags || $tags[-1] != 0x30;

my @required = @tags;
shift @required if $required[0] == 0xa0;
my @expected = (0x02, 0x18, 0x18, 0x06, 0x30);
die "Unexpected Manifest field layout\n"
	if "@required" ne "@expected";

my $content = substr($der, $outer_header,
	$offsets[-1] - $outer_header);
my $mutated = "\x30" . der_length(length($content)) . $content;

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $mutated;
close $out;
PERL
test "$?" -eq 0 || fail "Cannot remove ca1.mft's fileList field"

openssl asn1parse -inform DER -in "$MFT_WORK/content-mutated.der" \
	> "$MFT_WORK/asn1.txt" 2>&1 \
	|| fail "Manifest eContent without fileList is not valid DER"

resign_and_publish_manifest "$MANIFEST" \
	"$MFT_WORK/content-mutated.der" "$MFT_WORK" \
	"$SNAPSHOT" "$NOTIFICATION"

run_rp

check_vrps \
	"10.2.1.0/24-24 => AS64503" \
	"10.2.2.0/24-24 => AS64504"

check_http_requests \
	"/$TEST/ta.cer 200" \
	"/$TEST/notification.xml 200" \
	"/$TEST/snapshot.xml 200"

check_rsync_requests
