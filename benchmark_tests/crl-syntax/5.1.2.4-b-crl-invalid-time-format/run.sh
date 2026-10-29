#!/bin/sh

# Remove the seconds field from ca1.crl's UTCTime-encoded thisUpdate, then
# re-sign and republish the CRL. The entire ca1 branch must be rejected.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../common.sh"

crl_mutation_init

perl - "$CRL" "$WORK/mutated.crl" <<'PERL'
use strict;
use warnings;

my ($input, $output) = @ARGV;
open my $fh, '<:raw', $input or die "Cannot open $input: $!\n";
local $/;
my $crl = <$fh>;
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

sub children {
	my ($data, $offset, $wanted_tag) = @_;
	my ($tag, $header, $length, undef) = tlv($data, $offset);
	die sprintf("Expected tag 0x%02x, found 0x%02x\n",
		$wanted_tag, $tag) if $tag != $wanted_tag;
	my $at = $offset + $header;
	my $end = $at + $length;
	my @result;
	while ($at < $end) {
		my (undef, undef, undef, $total) = tlv($data, $at);
		push @result, $at;
		$at += $total;
	}
	die "DER child extends past its parent\n" if $at != $end;
	return @result;
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

sub sequence {
	my ($content) = @_;
	return "\x30" . der_length(length($content)) . $content;
}

sub replace_child {
	my ($data, $parent_offset, $child_offset, $replacement) = @_;
	my (undef, $parent_header, $parent_length, undef) =
		tlv($data, $parent_offset);
	my (undef, undef, undef, $child_total) = tlv($data, $child_offset);
	my $content_start = $parent_offset + $parent_header;
	my $content_end = $content_start + $parent_length;
	my $content = substr($data, $content_start,
		$child_offset - $content_start)
		. $replacement
		. substr($data, $child_offset + $child_total,
			$content_end - $child_offset - $child_total);
	return sequence($content);
}

my @outer = children($crl, 0, 0x30);
die "CertificateList does not contain three fields\n" if @outer != 3;
my $tbs_offset = $outer[0];
my @tbs = children($crl, $tbs_offset, 0x30);

my $index = 0;
my ($tag) = tlv($crl, $tbs[$index]);
$index++ if $tag == 0x02;
$index += 2; # signature and issuer
my $this_update_offset = $tbs[$index];
my ($time_tag, $time_header, $time_length, undef) =
	tlv($crl, $this_update_offset);
die "thisUpdate is not UTCTime\n" if $time_tag != 0x17;
my $time = substr($crl, $this_update_offset + $time_header, $time_length);
die "Unexpected canonical UTCTime: $time\n" if $time !~ /^\d{12}Z$/;

# RFC 5280 requires seconds. Deliberately encode YYMMDDHHMMZ instead.
my $invalid_time = substr($time, 0, 10) . 'Z';
my $replacement = "\x17" . der_length(length($invalid_time))
	. $invalid_time;
my $new_tbs = replace_child($crl, $tbs_offset,
	$this_update_offset, $replacement);
my $new_crl = replace_child($crl, 0, $tbs_offset, $new_tbs);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $new_crl;
close $out;
PERL
test "$?" -eq 0 || fail "Cannot remove seconds from ca1.crl thisUpdate"

extract_tbs_cert_list "$WORK/mutated.crl" "$WORK/tbs.der"
openssl dgst -sha256 -sign "$CRL_KEY" -out "$WORK/signature.bin" \
	"$WORK/tbs.der" || fail "Cannot re-sign ca1.crl"
replace_crl_signature "$WORK/mutated.crl" "$WORK/signature.bin" \
	"$WORK/resigned.crl"
mv "$WORK/resigned.crl" "$CRL"

openssl asn1parse -inform DER -in "$CRL" \
	> "$WORK/asn1.txt" 2>&1 || fail "Mutated ca1.crl is not valid DER"
grep -Eq 'UTCTIME.*[0-9]{10}Z' "$WORK/asn1.txt" \
	|| fail "ca1.crl does not contain the malformed UTCTime"
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
