#!/bin/sh

# Add SAFI=1 to ca1.cer's IPv4 addressFamily, then restore every affected
# signature and repository hash before running the RP.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../der-decoding/common.sh"
. "$SRCDIR/../4.8.5-common.sh"

CA="sandbox/rsyncd/content/$TEST/ta/ca1.cer"
TA="sandbox/rsyncd/content/$TEST/ta.cer"
MANIFEST="sandbox/rsyncd/content/$TEST/ta/ta.mft"
SNAPSHOT="sandbox/apache2/content/$TEST/snapshot.xml"
NOTIFICATION="sandbox/apache2/content/$TEST/notification.xml"
WORK="$SANDBOX/certificate-update"

# The stable key set is required to re-sign ca1.cer after adding one byte to
# the addressFamily OCTET STRING.
unset BARRY_GENERATE_KEYS
run_barry
mkdir -p "$WORK"

ORIGINAL_CA_HASH=$(sha256sum "$CA" | cut -d' ' -f1)
perl - "$CA" "$WORK/mutated-ca.cer" "$WORK/tbs.der" <<'PERL'
use strict;
use warnings;

my ($input, $output, $tbs_output) = @ARGV;

sub read_all {
	my ($path) = @_;
	open my $fh, '<:raw', $path or die "Cannot open $path: $!\n";
	local $/;
	my $data = <$fh>;
	close $fh;
	return $data;
}

sub parse_tlv {
	my ($data, $offset) = @_;
	die "Truncated DER tag\n" if $offset + 2 > length($data);
	my $tag = ord(substr($data, $offset, 1));
	my $first = ord(substr($data, $offset + 1, 1));
	my ($header, $length);
	if ($first < 128) {
		($header, $length) = (2, $first);
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
	return {
		tag => $tag,
		header => $header,
		length => $length,
		total => $header + $length,
		content => $offset + $header,
	};
}

sub split_tlvs {
	my ($data) = @_;
	my @items;
	my $offset = 0;
	while ($offset < length($data)) {
		my $tlv = parse_tlv($data, $offset);
		push @items, substr($data, $offset, $tlv->{total});
		$offset += $tlv->{total};
	}
	die "DER child boundary mismatch\n" if $offset != length($data);
	return @items;
}

sub content_of {
	my ($data) = @_;
	my $tlv = parse_tlv($data, 0);
	die "Trailing data after DER value\n" if $tlv->{total} != length($data);
	return substr($data, $tlv->{content}, $tlv->{length});
}

sub tag_of {
	return parse_tlv($_[0], 0)->{tag};
}

sub encode_length {
	my ($length) = @_;
	return chr($length) if $length < 128;
	my $encoded = '';
	while ($length) {
		$encoded = chr($length & 0xff) . $encoded;
		$length >>= 8;
	}
	return chr(0x80 | length($encoded)) . $encoded;
}

sub make_tlv {
	my ($tag, $content) = @_;
	return chr($tag) . encode_length(length($content)) . $content;
}

my $certificate = read_all($input);
die "Certificate is not a SEQUENCE\n" if tag_of($certificate) != 0x30;
my @certificate_fields = split_tlvs(content_of($certificate));
die "Unexpected Certificate field count\n" if @certificate_fields != 3;

my @tbs_fields = split_tlvs(content_of($certificate_fields[0]));
my $extensions_index = -1;
for my $i (0 .. $#tbs_fields) {
	next if tag_of($tbs_fields[$i]) != 0xa3;
	die "Multiple certificate extension containers\n"
		if $extensions_index >= 0;
	$extensions_index = $i;
}
die "Certificate extension container not found\n"
	if $extensions_index < 0;

my @wrapped = split_tlvs(content_of($tbs_fields[$extensions_index]));
die "Malformed Extensions wrapper\n"
	if @wrapped != 1 || tag_of($wrapped[0]) != 0x30;
my @extensions = split_tlvs(content_of($wrapped[0]));

# id-pe-ipAddrBlocks: 1.3.6.1.5.5.7.1.7
my $ip_oid = pack('H*', '06082b06010505070107');
my $ip_index = -1;
my (@ip_fields, $ip_value);
for my $i (0 .. $#extensions) {
	next if tag_of($extensions[$i]) != 0x30;
	my @fields = split_tlvs(content_of($extensions[$i]));
	next if !@fields || $fields[0] ne $ip_oid;
	die "Multiple IP Address Delegation extensions\n" if $ip_index >= 0;
	$ip_index = $i;
	@ip_fields = @fields;
	my @octets = grep { tag_of($_) == 0x04 } @fields;
	die "IP Address Delegation extension has no unique extnValue\n"
		if @octets != 1;
	$ip_value = content_of($octets[0]);
}
die "IP Address Delegation extension not found\n" if $ip_index < 0;
die "IPAddrBlocks is not a SEQUENCE\n" if tag_of($ip_value) != 0x30;

my @families = split_tlvs(content_of($ip_value));
my $changed = 0;
for my $i (0 .. $#families) {
	die "IPAddressFamily is not a SEQUENCE\n"
		if tag_of($families[$i]) != 0x30;
	my @family_fields = split_tlvs(content_of($families[$i]));
	die "Malformed IPAddressFamily\n"
		if @family_fields != 2 || tag_of($family_fields[0]) != 0x04;
	if (content_of($family_fields[0]) eq "\x00\x01") {
		# AFI 1 (IPv4), followed by SAFI 1 (unicast).
		$family_fields[0] = make_tlv(0x04, "\x00\x01\x01");
		$families[$i] = make_tlv(0x30, join('', @family_fields));
		$changed++;
	}
}
die "Expected exactly one IPv4 addressFamily\n" if $changed != 1;

my $new_ip_value = make_tlv(0x30, join('', @families));
my $replaced = 0;
for my $i (0 .. $#ip_fields) {
	if (tag_of($ip_fields[$i]) == 0x04) {
		$ip_fields[$i] = make_tlv(0x04, $new_ip_value);
		$replaced++;
	}
}
die "Expected one IP Address Delegation extnValue\n" if $replaced != 1;
$extensions[$ip_index] = make_tlv(0x30, join('', @ip_fields));

my $new_extensions = make_tlv(0x30, join('', @extensions));
$tbs_fields[$extensions_index] = make_tlv(0xa3, $new_extensions);
my $new_tbs = make_tlv(0x30, join('', @tbs_fields));
my $new_certificate = make_tlv(0x30,
	$new_tbs . $certificate_fields[1] . $certificate_fields[2]);

open my $out, '>:raw', $output or die "Cannot open $output: $!\n";
print {$out} $new_certificate;
close $out;
open my $tbs_out, '>:raw', $tbs_output
	or die "Cannot open $tbs_output: $!\n";
print {$tbs_out} $new_tbs;
close $tbs_out;
PERL
test "$?" -eq 0 || fail "Cannot add SAFI to ca1.cer"

# This helper is certificate-type agnostic despite its historical EKU name.
eku_resign_certificate "$WORK/mutated-ca.cer" "$WORK/tbs.der" "$TA" \
	"$WORK/signature.bin" "$WORK/resigned-ca.cer" "$WORK/ta-public.pem"
mv "$WORK/resigned-ca.cer" "$CA"
MUTATED_CA_HASH=$(sha256sum "$CA" | cut -d' ' -f1)

openssl x509 -inform DER -in "$CA" -noout -text \
	> "$WORK/certificate.txt" 2>&1 \
	|| fail "Mutated ca1.cer is not valid DER"
openssl asn1parse -inform DER -in "$CA" \
	> "$WORK/asn1.txt" 2>&1 \
	|| fail "Mutated ca1.cer cannot be parsed as DER"

rehash_and_resign_manifest \
	"$MANIFEST" "$ORIGINAL_CA_HASH" "$MUTATED_CA_HASH"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ta/ca1.cer" "$CA"
replace_snapshot_object "$SNAPSHOT" \
	"rsync://localhost:8873/rpki/$TEST/ta/ta.mft" "$MANIFEST"
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
