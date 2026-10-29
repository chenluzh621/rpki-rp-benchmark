#!/bin/sh

# BaRRy exposes only signerInfos.0 to RD overrides. Generate the baseline ROA,
# then duplicate that complete SignerInfo DER value and update only ancestor
# length octets. Both SignerInfos remain cryptographically valid.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../cms-signature/common.sh"

prepare_valid_roa

perl - "$ROA" <<'PERL'
use strict;
use warnings;

my ($path) = @ARGV;

sub read_all {
	my ($file) = @_;
	open my $input, '<:raw', $file or die "Cannot open $file: $!\n";
	local $/;
	my $data = <$input>;
	close $input;
	return $data;
}

sub write_all {
	my ($file, $data) = @_;
	open my $output, '>:raw', $file or die "Cannot write $file: $!\n";
	print {$output} $data;
	close $output;
}

sub der_length {
	my ($length) = @_;
	return chr($length) if $length < 0x80;
	my $encoded = '';
	while ($length) {
		$encoded = chr($length & 0xff) . $encoded;
		$length >>= 8;
	}
	return chr(0x80 | length($encoded)) . $encoded;
}

sub tlv {
	my ($tag, $value) = @_;
	return chr($tag) . der_length(length($value)) . $value;
}

sub parse_one {
	my ($data, $offset) = @_;
	die "Missing DER tag at offset $offset\n" if $offset >= length($data);
	my $start = $offset;
	my $tag = ord(substr($data, $offset++, 1));
	die "High-tag-number DER is not supported\n" if ($tag & 0x1f) == 0x1f;
	die "Missing DER length at offset $offset\n" if $offset >= length($data);
	my $first = ord(substr($data, $offset++, 1));
	my $length;
	if (($first & 0x80) == 0) {
		$length = $first;
	} else {
		my $octets = $first & 0x7f;
		die "Indefinite or oversized DER length\n"
			if $octets == 0 || $octets > 4 || $offset + $octets > length($data);
		$length = 0;
		for (1 .. $octets) {
			$length = ($length << 8) | ord(substr($data, $offset++, 1));
		}
	}
	die "DER value overruns its container\n" if $offset + $length > length($data);
	my $value = substr($data, $offset, $length);
	my $end = $offset + $length;
	return {
		tag => $tag,
		value => $value,
		full => substr($data, $start, $end - $start),
		end => $end,
	};
}

sub parse_all {
	my ($data) = @_;
	my @values;
	my $offset = 0;
	while ($offset < length($data)) {
		my $value = parse_one($data, $offset);
		push @values, $value;
		$offset = $value->{end};
	}
	return @values;
}

my $roa = read_all($path);
my $content_info = parse_one($roa, 0);
die "ContentInfo is not one complete SEQUENCE\n"
	if $content_info->{tag} != 0x30 || $content_info->{end} != length($roa);

my @content_info_fields = parse_all($content_info->{value});
die "Unexpected ContentInfo field layout\n"
	if @content_info_fields != 2 || $content_info_fields[0]->{tag} != 0x06
	|| $content_info_fields[1]->{tag} != 0xa0;

my $signed_data = parse_one($content_info_fields[1]->{value}, 0);
die "SignedData is not one complete SEQUENCE\n"
	if $signed_data->{tag} != 0x30
	|| $signed_data->{end} != length($content_info_fields[1]->{value});

my @signed_data_fields = parse_all($signed_data->{value});
die "SignedData has no signerInfos SET\n"
	if !@signed_data_fields || $signed_data_fields[-1]->{tag} != 0x31;

my $signer_infos = pop @signed_data_fields;
my @signers = parse_all($signer_infos->{value});
die "Expected exactly one original SignerInfo, found " . scalar(@signers) . "\n"
	if @signers != 1 || $signers[0]->{tag} != 0x30;

my $new_signer_infos = tlv(0x31, $signers[0]->{full} . $signers[0]->{full});
my $new_signed_data_value = join('', map { $_->{full} } @signed_data_fields)
	. $new_signer_infos;
my $new_signed_data = tlv(0x30, $new_signed_data_value);
my $new_explicit_content = tlv(0xa0, $new_signed_data);
my $new_content_info = tlv(0x30,
	$content_info_fields[0]->{full} . $new_explicit_content);

# Parse the rebuilt hierarchy again and assert that it now has two signers.
my $check_ci = parse_one($new_content_info, 0);
my @check_ci_fields = parse_all($check_ci->{value});
my $check_sd = parse_one($check_ci_fields[1]->{value}, 0);
my @check_sd_fields = parse_all($check_sd->{value});
my @check_signers = parse_all($check_sd_fields[-1]->{value});
die "Expected two mutated SignerInfos, found " . scalar(@check_signers) . "\n"
	if @check_signers != 2;

write_all($path, $new_content_info);
PERL
test "$?" -eq 0 || fail "Cannot duplicate roa1-1.roa SignerInfo"

openssl asn1parse -inform DER -in "$ROA" \
	> "$CMS_WORK/two-signers-asn1.txt" 2>&1 \
	|| fail "The two-SignerInfo ROA is not valid DER"

# OpenSSL verifies every SignerInfo. Success here proves the duplicated values
# are valid signatures and that signerInfos cardinality is the intended fault.
openssl cms -verify -binary -inform DER -in "$ROA" -noverify \
	-out "$CMS_WORK/two-signers-content.der" \
	> "$CMS_WORK/two-signers-verify.log" 2>&1 \
	|| fail "The duplicated SignerInfos are not both cryptographically valid"
cmp -s "$CMS_WORK/original-content.der" "$CMS_WORK/two-signers-content.der" \
	|| fail "Duplicating SignerInfo unexpectedly changed ROA eContent"

publish_mutated_roa

run_rp
check_only_target_roa_rejected
