#!/bin/sh

# Construct a valid ROA whose sole SignerInfo carries one prohibited
# unsignedAttrs entry. The original signedAttrs and signature stay unchanged.
. tools/checks.sh
. rp/$RP.sh
. "$SRCDIR/../../cms-signature/common.sh"

prepare_valid_roa
UNSIGNED_ATTRS_WORK="$CMS_WORK/unsigned-attrs"
mkdir -p "$UNSIGNED_ATTRS_WORK"

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
			if $octets == 0 || $octets > 4
			|| $offset + $octets > length($data);
		$length = 0;
		for (1 .. $octets) {
			$length = ($length << 8) | ord(substr($data, $offset++, 1));
		}
	}
	die "DER value overruns its container\n"
		if $offset + $length > length($data);
	my $end = $offset + $length;
	return {
		tag => $tag,
		value => substr($data, $offset, $length),
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

my $cms = read_all($path);
my $content_info = parse_one($cms, 0);
die "ContentInfo is not one complete SEQUENCE\n"
	if $content_info->{tag} != 0x30 || $content_info->{end} != length($cms);
my @content_info_fields = parse_all($content_info->{value});
die "Unexpected ContentInfo layout\n"
	if @content_info_fields != 2 || $content_info_fields[1]->{tag} != 0xa0;
my $signed_data = parse_one($content_info_fields[1]->{value}, 0);
die "SignedData is not one complete SEQUENCE\n"
	if $signed_data->{tag} != 0x30
	|| $signed_data->{end} != length($content_info_fields[1]->{value});
my @signed_data_fields = parse_all($signed_data->{value});
die "SignedData does not end with signerInfos\n"
	if !@signed_data_fields || $signed_data_fields[-1]->{tag} != 0x31;
my @signer_infos = parse_all($signed_data_fields[-1]->{value});
die "Expected exactly one SignerInfo\n"
	if @signer_infos != 1 || $signer_infos[0]->{tag} != 0x30;
my @signer_info_fields = parse_all($signer_infos[0]->{value});
die "Baseline SignerInfo already contains unsignedAttrs\n"
	if grep { $_->{tag} == 0xa1 } @signer_info_fields;
die "SignerInfo does not end with a signature OCTET STRING\n"
	if !@signer_info_fields || $signer_info_fields[-1]->{tag} != 0x04;
my $original_signature = $signer_info_fields[-1]->{full};

# Attribute { attrType 1.2.3.4, attrValues SET OF { NULL } }.
my $attribute = tlv(0x30,
	tlv(0x06, pack('H*', '2a0304')) . tlv(0x31, tlv(0x05, '')));
push @signer_info_fields, { full => tlv(0xa1, $attribute) };

my $new_signer_info = tlv(0x30,
	join('', map { $_->{full} } @signer_info_fields));
$signed_data_fields[-1] = { full => tlv(0x31, $new_signer_info) };
my $new_signed_data = tlv(0x30,
	join('', map { $_->{full} } @signed_data_fields));
$content_info_fields[1] = { full => tlv(0xa0, $new_signed_data) };
my $new_content_info = tlv(0x30,
	join('', map { $_->{full} } @content_info_fields));

my $check_ci = parse_one($new_content_info, 0);
my @check_ci_fields = parse_all($check_ci->{value});
my $check_sd = parse_one($check_ci_fields[1]->{value}, 0);
my @check_sd_fields = parse_all($check_sd->{value});
my @check_signer_infos = parse_all($check_sd_fields[-1]->{value});
my @check_si_fields = parse_all($check_signer_infos[0]->{value});
my @check_unsigned = grep { $_->{tag} == 0xa1 } @check_si_fields;
die "Expected exactly one unsignedAttrs field\n" if @check_unsigned != 1;
my @check_attributes = parse_all($check_unsigned[0]->{value});
die "unsignedAttrs does not contain the intended attribute\n"
	if @check_attributes != 1 || $check_attributes[0]->{full} ne $attribute;
die "Adding unsignedAttrs changed the CMS signature\n"
	if $check_si_fields[-2]->{full} ne $original_signature;

write_all($path, $new_content_info);
PERL
test "$?" -eq 0 || fail "Cannot add SignerInfo.unsignedAttrs"

openssl cms -cmsout -inform DER -in "$ROA" -print \
	> "$UNSIGNED_ATTRS_WORK/cms-print.txt" 2>&1 \
	|| fail "The unsignedAttrs ROA is not valid DER CMS"
openssl cms -verify -binary -inform DER -in "$ROA" -noverify \
	-out "$UNSIGNED_ATTRS_WORK/content.der" \
	> "$UNSIGNED_ATTRS_WORK/verify.log" 2>&1 \
	|| fail "Adding unsignedAttrs unexpectedly invalidated the CMS signature"
cmp -s "$CMS_WORK/original-content.der" "$UNSIGNED_ATTRS_WORK/content.der" \
	|| fail "Adding unsignedAttrs unexpectedly changed ROA eContent"

publish_mutated_roa
run_rp
check_only_target_roa_rejected
