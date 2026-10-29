#!/bin/sh

# Merge two BaRRy CP placeholders into one Certificate Policies extension
# containing two PolicyInformation entries, then restore all affected
# signatures and repository hashes.
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

# Use the stable key set so ca1.cer can be re-signed after its DER length
# changes. No RP sees the intermediate certificate with duplicate extensions.
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

my $cp_oid = pack('H*', '0603551d20');
my (@cp_indexes, @cp_values, @cp_fields);
for my $i (0 .. $#extensions) {
	next if tag_of($extensions[$i]) != 0x30;
	my @fields = split_tlvs(content_of($extensions[$i]));
	next if !@fields || $fields[0] ne $cp_oid;
	my @octets = grep { tag_of($_) == 0x04 } @fields;
	die "Certificate Policies extension has no unique extnValue\n"
		if @octets != 1;
	push @cp_indexes, $i;
	push @cp_values, content_of($octets[0]);
	push @cp_fields, \@fields;
}
die "Expected two Certificate Policies placeholders\n"
	if @cp_indexes != 2;

my @policies;
for my $value (@cp_values) {
	die "CertificatePolicies is not a SEQUENCE\n"
		if tag_of($value) != 0x30;
	my @entries = split_tlvs(content_of($value));
	die "Each placeholder must contain exactly one PolicyInformation\n"
		if @entries != 1 || tag_of($entries[0]) != 0x30;
	push @policies, $entries[0];
}

# Keep the first extension and place both PolicyInformation values inside its
# extnValue. Remove the second placeholder extension altogether.
my $multiple_policies = make_tlv(0x30, join('', @policies));
my @first_fields = @{$cp_fields[0]};
my $replaced = 0;
for my $i (0 .. $#first_fields) {
	if (tag_of($first_fields[$i]) == 0x04) {
		$first_fields[$i] = make_tlv(0x04, $multiple_policies);
		$replaced++;
	}
}
die "Expected one extnValue in the retained CP extension\n"
	if $replaced != 1;
$extensions[$cp_indexes[0]] = make_tlv(0x30, join('', @first_fields));
splice @extensions, $cp_indexes[1], 1;

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
test "$?" -eq 0 || fail "Cannot construct multiple Certificate Policies"

# The signing helper is certificate-type agnostic: it locates the issuer key,
# signs the rebuilt TBSCertificate, and replaces the outer signature value.
eku_resign_certificate "$WORK/mutated-ca.cer" "$WORK/tbs.der" "$TA" \
	"$WORK/signature.bin" "$WORK/resigned-ca.cer" "$WORK/ta-public.pem"
mv "$WORK/resigned-ca.cer" "$CA"
MUTATED_CA_HASH=$(sha256sum "$CA" | cut -d' ' -f1)

openssl x509 -inform DER -in "$CA" -noout -ext certificatePolicies \
	> "$WORK/certificate-policies.txt" 2>&1 \
	|| fail "Mutated ca1.cer is not valid DER"
test "$(grep -c 'Policy:' "$WORK/certificate-policies.txt")" -eq 2 \
	|| fail "ca1.cer does not contain exactly two PolicyInformation entries"

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
